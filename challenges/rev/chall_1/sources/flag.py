import base64

flag = "SSI{Uncr4ckab13_paSSw0rD}"
print(base64.b64encode(bytes([ ord(i)^0x69 for i in flag ])))
