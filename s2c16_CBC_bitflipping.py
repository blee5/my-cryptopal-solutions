import AES
import os
import CryptoPalTools as cpt

key = bytearray(os.urandom(16))
iv = bytearray(os.urandom(16))

def prepare_input_data(input_data):
    input_data = input_data.replace(b';',b'%3b').replace(b'=',b'%3d')
    plaintext = b"comment1=cooking;date=8/28/2018;level=152;userdata=" + input_data + b";comment2=like_a_pound_of_bacon"
    return AES.aes_128_cbc_enc(plaintext, key, iv)

def is_admin(ciphertext):
    plaintext = AES.aes_128_cbc_dec(ciphertext, key, iv)
    return (b'admin=true') in plaintext.split(b';')

def get_admin_account():
    block_size = cpt.get_block_size(prepare_input_data)

    prefix_length = len(b"comment1=cooking;date=8/28/2018;level=152;userdata=")
    if prefix_length % block_size:
        offset = (prefix_length // block_size + 1) * block_size
    else:
        offset = (prefix_length // block_size) * block_size
    pad_amount = offset - prefix_length

    ciphertext = prepare_input_data(b'B' * (pad_amount + block_size)+ b'AadminAtrue')
    prefix_blocks = ciphertext[:offset+block_size]
    body = ciphertext[offset+block_size:]

    # xor returns a bytearray so I have to index to get the actual byte value..
    prefix_blocks[offset] ^= cpt.xor(b'A', b';')[0]
    prefix_blocks[offset + 6] ^= cpt.xor(b'A', b'=')[0]

    edited = prefix_blocks + body
    assert is_admin(edited)

get_admin_account()