#!/usr/bin/env bash
# Copyright (C) 2026 OPENOS-dev
# This program is free software: you can redistribute it and/or modify
# it under the terms of the OPENOS-PROJECT-LICENSE (OPL) v1.2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# OPL for more details.
#
# You should have received a copy of the OPL along with this program.
# If not, see <https://github.com/OPENOS-dev/OPL>.
#
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
