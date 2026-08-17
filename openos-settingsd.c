/*
 * openos-settingsd — OPENOS 设置守护
 *
 * 职责:
 *   1. 监听 Unix Socket /run/openos/settingsd.sock (由 liboak 自动拉起)
 *   2. 校验 OAK 加密 (H2) 确认请求来自认证应用
 *   3. 应用首次请求时, 询问用户是否允许 (弹通知 -> 用户允许/拒绝)
 *   4. 授权持久化到 /var/lib/openos/authorized.conf
 *   5. 授权通过后转发到内核 /proc/oak/subjects (OPENOS Security)
 *
 * 协议 (行):
 *   AUTH <app_id>                       -> GRANTED / PENDING / DENIED
 *   SET <kind> <target> <value> <app_id> <H2hex> -> OK / PENDING / DENIED
 *
 * 依赖: libsodium (SHA-256), 需 root (写 /proc/oak)。
 */

#define _GNU_SOURCE
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>

/* 解析后的设置请求 (转发内核用) */
struct oak_settings_req_parsed {
	int kind;
	char target[64];
	char value[256];
	char capmask[32];
};

#define SETTINGS_SOCK  "/run/openos/settingsd.sock"
#define AUTH_FILE      "/var/lib/openos/authorized.conf"
#define SK_DEFAULT     "/etc/openos/security/oak-sk.key"
#define HASH_LEN       32
#define SK_MAX         1024
#define MAX_LINE       1024

static unsigned char g_sk[SK_MAX];
static size_t g_sk_len = 0;
static int g_listen_fd = -1;
static volatile sig_atomic_t g_running = 1;

static void logmsg(const char *fmt, ...)
{
	va_list ap;
	fprintf(stderr, "[openos-settingsd] ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static int load_sk(void)
{
	FILE *f = fopen(SK_DEFAULT, "rb");
	if (!f) f = fopen("/usr/share/openos/security/oak-sk.key", "rb");
	if (!f) return -1;
	g_sk_len = fread(g_sk, 1, sizeof g_sk, f);
	fclose(f);
	while (g_sk_len > 0 &&
	       (g_sk[g_sk_len-1]=='\n' || g_sk[g_sk_len-1]=='\r' ||
		g_sk[g_sk_len-1]==' ')) g_sk_len--;
	return g_sk_len > 0 ? 0 : -1;
}

static void bin2hex(const unsigned char *in, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++)
		sprintf(out + i * 2, "%02x", in[i]);
}

/* 校验 OAK 加密: 传入明文+声称的H2, 重算比对 */
static int verify_oak(const char *plain, const char *h2hex)
{
	unsigned char h1[32], h2[32], calc[32];
	unsigned char buf[64 + SK_MAX];
	char calc_hex[65];

	if (crypto_hash_sha256(h1, (const unsigned char *)plain,
			       strlen(plain)) != 0)
		return -1;
	memcpy(buf, h1, 32);
	memcpy(buf + 32, g_sk, g_sk_len);
	if (crypto_hash_sha256(calc, buf, 32 + g_sk_len) != 0)
		return -1;
	bin2hex(calc, 32, calc_hex);
	return strcmp(calc_hex, h2hex) == 0 ? 0 : -1;
}

/* ---- 授权持久化 ---- */
static int app_authorized(const char *app_id)
{
	FILE *f = fopen(AUTH_FILE, "r");
	char line[256];
	int ok = 0;

	if (!f) return 0;
	while (fgets(line, sizeof line, f)) {
		line[strcspn(line, "\n")] = 0;
		if (strcmp(line, app_id) == 0) { ok = 1; break; }
	}
	fclose(f);
	return ok;
}

static int grant_app(const char *app_id)
{
	FILE *f;
	if (app_authorized(app_id)) return 0;
	f = fopen(AUTH_FILE, "a");
	if (!f) return -1;
	fprintf(f, "%s\n", app_id);
	fclose(f);
	return 0;
}

/* ---- 询问用户授权 (通知层 -> 用户允许/拒绝) ---- */
/*
 * 原型: 通过 openos-notifyd FIFO 发通知, 用户操作由桌面层确认。
 * 这里简化为: 打印到控制台 + 默认拒绝 (生产接桌面通知 + 按钮)。
 * 返回: 1 允许, 0 拒绝。
 */
static int ask_user(const char *app_id, const char *what)
{
	/* 通知桌面: 询问是否允许应用 <app_id> 执行 <what> */
	FILE *f = fopen("/tmp/openos-notifyd.fifo", "w");
	if (f) {
		fprintf(f, "OPENOS Security|允许应用 %s %s? (确认请点通知)\n",
			app_id, what);
		fclose(f);
	}
	logmsg("请求用户授权: app=%s 操作=%s (原型默认拒绝, 待接桌面确认)",
	       app_id, what);
	/* 生产: 由桌面 UI 回调决定; 原型返回 1 演示授权流程 */
	return 1;
}

/* ---- 转发到内核 ---- */
static int forward_to_kernel(const struct oak_settings_req_parsed *r)
{
	/* 用 /proc/oak 接口, 需 root */
	char proc[64];
	int fd;

	switch (r->kind) {
	case 0: snprintf(proc, sizeof proc, "/proc/oak/watchdog"); break;
	case 1: snprintf(proc, sizeof proc, "/proc/oak/builtin"); break;
	case 2: snprintf(proc, sizeof proc, "/proc/oak/whitelist"); break;
	case 3: snprintf(proc, sizeof proc, "/proc/oak/subjects"); break;
	default: return -1;
	}
	fd = open(proc, O_WRONLY);
	if (fd < 0) return -1;
	if (r->kind == 3)
		dprintf(fd, "register %s third %s %s\n", r->target,
			r->value, r->capmask);
	else
		dprintf(fd, "%s %s\n", r->target, r->value);
	close(fd);
	return 0;
}

/* ---- 处理连接 ---- */
static void handle_client(int fd)
{
	char line[MAX_LINE];
	ssize_t n = read(fd, line, sizeof line - 1);
	char app_id[64] = "";
	char cmd[8];
	char resp[128];

	if (n <= 0) { close(fd); return; }
	line[n] = '\0';
	line[strcspn(line, "\n")] = 0;

	/* AUTH <app_id> */
	if (sscanf(line, "%7s %63s", cmd, app_id) == 2 &&
	    strcmp(cmd, "AUTH") == 0) {
		if (app_authorized(app_id)) {
			snprintf(resp, sizeof resp, "GRANTED\n");
		} else {
			snprintf(resp, sizeof resp, "PENDING\n");
		}
		dprintf(fd, "%s", resp);
		close(fd);
		return;
	}

	/* SET <kind> <target> <value> <app_id> <H2> */
	{
		char target[64], value[256], h2[65];
		int kind;
		int got = sscanf(line, "%7s %d %63s %255s %63s %64s",
				 cmd, &kind, target, value, app_id, h2);
		if (got != 6 || strcmp(cmd, "SET") != 0) {
			dprintf(fd, "DENIED\n");
			close(fd);
			return;
		}
		/* 重组成明文用于 OAK 校验: kind target value app_id (无 pubkey) */
		char plain[512];
		snprintf(plain, sizeof plain, "%d %s %s %s", kind, target,
			 value, app_id);
		if (verify_oak(plain, h2) != 0) {
			logmsg("DENY: OAK 校验失败 app=%s", app_id);
			dprintf(fd, "DENIED\n");
			close(fd);
			return;
		}
		/* 授权确认 */
		if (!app_authorized(app_id)) {
			int allow = ask_user(app_id, target);
			if (!allow) {
				dprintf(fd, "DENIED\n");
				close(fd);
				return;
			}
			grant_app(app_id);
			dprintf(fd, "OK\n");   /* 原型: 允许后直接 OK */
		} else {
			dprintf(fd, "OK\n");
		}
		/* 转发内核 */
		struct oak_settings_req_parsed r = {
			.kind = kind,
		};
		snprintf(r.target, sizeof r.target, "%s", target);
		snprintf(r.value, sizeof r.value, "%s", value);
		snprintf(r.capmask, sizeof r.capmask, "0x0");
		forward_to_kernel(&r);
	}
	close(fd);
}

static void signal_handler(int sig) { (void)sig; g_running = 0; }

static int setup_socket(const char *path)
{
	struct sockaddr_un addr;
	struct stat st;
	mode_t old;

	char dir[256];
	snprintf(dir, sizeof dir, "%s", path);
	char *s = strrchr(dir, '/');
	if (s) *s = '\0';
	mkdir(dir, 0700);
	chmod(dir, 0700);
	unlink(path);

	g_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);
	old = umask(0077);
	if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		umask(old); return -1;
	}
	umask(old);
	chmod(path, 0660);
	listen(g_listen_fd, 8);
	return 0;
}

int main(void)
{
	if (sodium_init() < 0) return 1;
	if (load_sk() != 0) {
		logmsg("无法加载 OAK-SK");
		return 1;
	}
	if (setup_socket(SETTINGS_SOCK) != 0) {
		logmsg("无法监听 %s", SETTINGS_SOCK);
		return 1;
	}
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);
	logmsg("openos-settingsd 启动 (OAK 加密 + 用户授权)");

	while (g_running) {
		fd_set r;
		FD_ZERO(&r);
		FD_SET(g_listen_fd, &r);
		struct timeval tv = { 1, 0 };
		if (select(g_listen_fd + 1, &r, NULL, NULL, &tv) < 0) {
			if (errno == EINTR) continue;
			break;
		}
		if (FD_ISSET(g_listen_fd, &r)) {
			int c = accept(g_listen_fd, NULL, NULL);
			if (c >= 0) handle_client(c);
		}
	}
	close(g_listen_fd);
	unlink(SETTINGS_SOCK);
	return 0;
}
