/*
 * oak-test-client — OAK 协议测试客户端
 * 用法: oak-test-client <command> [OAK-SK] [socket]
 *   - 用与守护进程相同算法生成 H1 与 H2, 发送并打印响应
 */
#define _GNU_SOURCE
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define HASH_LEN 32
#define SK_MAX   1024
#define DEFAULT_SOCKET "/run/openos/oak.sock"
#define DEFAULT_SK     "../KEYS/.private/oak-sk.key"

static void bin2hex(const unsigned char *in, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++)
		sprintf(out + i * 2, "%02x", in[i]);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "用法: %s <command> [OAK-SK] [socket]\n", argv[0]);
		return 1;
	}
	const char *cmd = argv[1];
	const char *sk_path = (argc > 2) ? argv[2] : DEFAULT_SK;
	const char *sock_path = (argc > 3) ? argv[3] : DEFAULT_SOCKET;

	if (sodium_init() < 0) {
		fprintf(stderr, "libsodium 初始化失败\n");
		return 1;
	}

	unsigned char sk[SK_MAX];
	FILE *f = fopen(sk_path, "rb");
	if (!f) { perror("打开 OAK-SK"); return 1; }
	size_t sklen = fread(sk, 1, sizeof sk, f);
	fclose(f);
	while (sklen > 0 && (sk[sklen-1]=='\n'||sk[sklen-1]=='\r'||sk[sklen-1]==' '))
		sklen--;

	/* H1 = SHA256(timestamp||cmd)  -- 演示用, 客户端自定义 */
	char ts[32];
	snprintf(ts, sizeof ts, "%ld", (long)time(NULL));
	unsigned char h1[HASH_LEN];
	unsigned char tmp[128];
	int tlen = snprintf((char*)tmp, sizeof tmp, "%s%s", ts, cmd);
	crypto_hash_sha256(h1, tmp, (size_t)tlen);
	char h1hex[HASH_LEN*2+1];
	bin2hex(h1, HASH_LEN, h1hex);

	/* 组装请求行 */
	char req[256];
	snprintf(req, sizeof req, "%s %s %s\n", ts, cmd, h1hex);

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) { perror("socket"); return 1; }
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sock_path, sizeof addr.sun_path - 1);
	if (connect(fd, (struct sockaddr*)&addr, sizeof addr) < 0) {
		perror("connect"); close(fd); return 1;
	}
	write(fd, req, strlen(req));
	char resp[512];
	int n = read(fd, resp, sizeof resp - 1);
	if (n > 0) { resp[n] = 0; printf("服务端响应: %s", resp); }
	close(fd);
	return 0;
}
