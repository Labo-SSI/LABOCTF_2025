from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json
import os


KEY = os.urandom(16)


def get_flag():
    out = ""
    with open("flag.txt") as f:
        out = f.read()
    return out


def get_token():
    iv: bytes = os.urandom(16)
    payload: bytes = json.dumps({"root": 0}).encode()
    token: str = encrypt(payload, iv)
    return iv.hex() + token


def encrypt(message: bytes, iv: bytes) -> str:
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    padded_message: bytes = pad(message, 16)
    encrypted: bytes = cipher.encrypt(padded_message)
    return encrypted.hex()


def login(hex_token: str) -> bool:
    token = bytes.fromhex(hex_token)
    iv = token[:16]
    payload = token[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    try:
        decoded = cipher.decrypt(payload)
        unpadded = unpad(decoded, 16)
        # print(f"[DEBUG]: {unpadded}")
        content = json.loads(unpadded)
        if content["root"] != 0:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error while decoding: {e}")
        return False


def prompt():
    print("Options:")
    print("1. Get a guest token")
    print("2. Log in to get the flag")
    print("3. Leave")
    result = input("Choice? (1/2/3): ")
    if result == "1":
        print("Here is your guest token:")
        print(get_token())
    elif result == "2":
        token = input("Please give me your token: ")
        if login(token):
            print(get_flag())
            exit()
        else:
            print("You are guest or your token is invalid")
    elif result == "3":
        print("Goodbye!")
        exit()
    else:
        print("Invalid choice")
        prompt()


def main():
    print("Welcome! If you want the flag, please log in.")
    while True:
        prompt()


if __name__ == "__main__":
    main()
