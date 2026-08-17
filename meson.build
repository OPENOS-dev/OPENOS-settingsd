# openos-settingsd — 设置守护 (OAK 加密 + 用户授权 + 转发内核)
project('openos-settingsd', 'c', default_options: ['c_std=c11'])

libsodium = dependency('libsodium')

executable('openos-settingsd',
  sources: ['openos-settingsd.c'],
  dependencies: [libsodium],
  install: true)

# 测试客户端
executable('oak-test-client',
  sources: ['oak-test-client.c'],
  dependencies: [libsodium],
  install: false)
