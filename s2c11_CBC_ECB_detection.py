from random import randint
import os
import CryptoPalTools as cpt
import AES

def random_aes_key():
    return bytearray(os.urandom(16))

def random_encryption(plaintext):
    plaintext = bytearray(os.urandom(randint(0,30))) + plaintext + bytearray(os.urandom(randint(0,30)))
    if (randint(0,1) == 1):
        # CBC
        ciphertext = AES.aes_128_cbc_enc(plaintext, random_aes_key(), random_aes_key())
        return ciphertext, 'CBC'
    else:
        # ECB
        ciphertext = AES.aes_128_ecb_enc(plaintext, random_aes_key())
        return ciphertext, 'ECB'

def repeated_blocks(b, block_length=16):
    blocks = []
    for i in range(0, len(b), block_length):
        block = bytes(b[i:i + block_length])
        if block in blocks:
            return True
        else:
            blocks.append(block)
    return False

def detect_scheme(plaintext):
    for i in range(1000):
        testdata = random_encryption(plaintext)
        ciphertext = testdata[0]

        if repeated_blocks(ciphertext):
            encryption_type = 'ECB'
        else:
            encryption_type = 'CBC'

        if testdata[1] != encryption_type:
            print("FAIL")
            print(testdata[1])
            return

detect_scheme(b'YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE')