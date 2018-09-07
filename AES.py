import CryptoPalTools as cpt
import base64
import os
from Crypto.Cipher import AES

def aes_128_ecb_enc(plaintext, key, pad_input=True):
    obj = AES.new(key, AES.MODE_ECB)
    if pad_input:
        plaintext = cpt.pcks7pad(plaintext)
    return bytearray(obj.encrypt(plaintext))

def aes_128_ecb_dec(ciphertext, key, unpad_output=True):
    obj = AES.new(key, AES.MODE_ECB)
    out = bytearray(obj.decrypt(ciphertext))
    if unpad_output:
        return cpt.pcks7unpad(out)
    else:
        return out

def aes_128_cbc_enc(plaintext, key, iv, pad_input=True):
    if pad_input:
        plaintext = cpt.pcks7pad(plaintext)
    ciphertext = bytearray(len(plaintext))
    prev_block = iv
    for i in range(0, len(plaintext), AES.block_size):
        ciphertext[i:i + AES.block_size] = aes_128_ecb_enc(cpt.xor(plaintext[i:i+AES.block_size], prev_block), key, False)
        prev_block = ciphertext[i:i+AES.block_size]
    return ciphertext
    
def aes_128_cbc_dec(ciphertext, key, iv, unpad_output=True):
    plaintext = bytearray(len(ciphertext))
    prev_block = iv
    for i in range(0, len(plaintext), AES.block_size):
        plaintext[i:i+AES.block_size] = cpt.xor(prev_block, aes_128_ecb_dec(ciphertext[i:i+AES.block_size], key, False))
        prev_block = ciphertext[i:i+AES.block_size]
    if unpad_output:
        return cpt.pcks7unpad(plaintext)
    else:
        return plaintext

def test_aes():
    plaintext = b'This is a secret message'
    key = os.urandom(16)
    iv = os.urandom(16)

    assert plaintext == aes_128_ecb_dec(aes_128_ecb_enc(plaintext, key), key)
    assert plaintext == aes_128_cbc_dec(aes_128_cbc_enc(plaintext, key, iv), key, iv)

if __name__ == "__main__":
    test_aes()