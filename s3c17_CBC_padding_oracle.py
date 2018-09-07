from random import randint
import AES
import os
import base64

strings = b"""VGVzdCBzdHJpbmcgbnVtYmVyIG9uZQ==
QW5vdGhlciB0ZXN0IHN0cmluZw==
SWYgeW91IGFyZSByZWFkaW5nIHRoaXMsIHlheSE=
Li4uc3Bvb2t5Li4uLg==
QW50b25pbyBUYW5hYnVyZW5pc2F1IChib3JuIDE5NDgpIGlzIGEgZm9ybWVyIEZpamlhbiBwb2xpdGljaWFuLg==
R3JvdXAgQyBvZiBVRUZBIEV1cm8gMjAxNiBjb250YWluZWQgR2VybWFueSwgVWtyYWluZSwgUG9sYW5kIGFuZCBOb3J0aGVybiBJcmVsYW5kLg==""".split()

key = os.urandom(16)
iv = os.urandom(16)

def random_ciphertext():
    plaintext = base64.b64decode(strings[randint(0, len(strings) - 1)])
    ciphertext = AES.aes_128_cbc_enc(plaintext, key, iv)
    return ciphertext, iv

def padding_oracle(ciphertext):
    plaintext = AES.aes_128_cbc_dec(ciphertext, key, iv, False)
    # print(plaintext)
    padding = plaintext[-1]
    if padding == 0:
        return False
    for i in range(len(plaintext) - 1, len(plaintext) - padding, -1):
        if plaintext[i] != plaintext[i - 1]:
            return False
    return True

def crack_block(block, prev_block):
    plaintext_block = bytearray(16)
    for i in range(16):
        prev_block_copy = bytearray(prev_block)
        padding = i + 1
        # Use the plaintext bytes we found to generate valid padding
        for j in range(1, padding):
            prev_block_copy[-j] ^= padding ^ plaintext_block[-j]
        # Guess the next plaintext byte
        for byte in range(256):
            prev_block_copy[-padding] ^= byte
            if padding_oracle(prev_block_copy + block):
                plaintext_block[-padding] = padding ^ byte
            prev_block_copy[-padding] ^= byte # xor again to reset
    return plaintext_block

def main():
    ciphertext, iv = random_ciphertext()
    plaintext = bytearray()
    for i in range(len(ciphertext) // 16):
        cur_block = ciphertext[i * 16 : (i + 1) * 16]
        if i == 0:
            prev_block = iv
        else:
            prev_block = ciphertext[(i - 1) * 16 : i * 16]
        plaintext += crack_block(cur_block, prev_block)
    print(plaintext)

main()