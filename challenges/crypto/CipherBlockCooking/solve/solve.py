from pwn import *
from Crypto.Util.Padding import pad, unpad

context.log_level = "error"

# p = process(["python", "server.py"])

p = remote("127.0.0.1", 10101)

token = p.recvuntil(b": ")

p.sendline(b"1")

p.recvuntil(b"token:")
p.recvline()
hex_token = p.recvline(keepends=False).decode()
# print(hex_token)
token = bytes.fromhex(hex_token)

original_iv = token[:16]
original_enc_payload = token[16:]

original_payload = pad(b'{"root": 0}', 16)
expected_payload = pad(b'{"root": 1}', 16)

new_iv = xor(original_payload, expected_payload, original_iv)

new_token: bytes = new_iv + original_enc_payload
new_token_hex: str = new_token.hex()

p.recvuntil(b": ")

p.sendline(b"2")
p.recvuntil(b": ")

p.sendline(new_token_hex.encode())

p.recvline()
print(p.recvline(keepends=False).decode())
