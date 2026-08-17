#!/usr/bin/env bash
# 构建 OPENOS Settings API + 设置守护 (需 libsodium)
#   liboak.a         静态库 (应用链接)
#   openos-settingsd 设置守护
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "== 构建 liboak (静态库) =="
cc -O2 -Wall -c -o "$DIR/liboak.o" "$DIR/liboak.c" -lsodium
ar rcs "$DIR/liboak.a" "$DIR/liboak.o"

echo "== 构建 openos-settingsd =="
cc -O2 -Wall -o "$DIR/openos-settingsd" "$DIR/openos-settingsd.c" -lsodium

echo "完成:"
echo "  $DIR/liboak.a"
echo "  $DIR/openos-settingsd"
echo "应用编译时: cc app.c liboak.a -lsodium"
