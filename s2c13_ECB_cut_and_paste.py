import AES
import os
import CryptoPalTools as cpt

key = os.urandom(16) 

def str_to_dict(string):
    obj = {}
    for kv in string.split("&"):
        kv = kv.split("=")
        obj[kv[0]] = kv[1]
    return obj

def profile_for(email):
    email.replace(b'&', b'').replace(b'=', b'')
    profile = b"email=" + email + b"&uid=10&role=user"
    return AES.aes_128_ecb_enc(profile, key)

def dec_profile(profile):
    plaintext = AES.aes_128_ecb_dec(profile, key)
    decoded = bytearray(plaintext).decode()
    return str_to_dict(decoded)

def get_block_size(oracle):
    known_length = len(oracle(b''))
    i = 1
    while True:
        data = bytearray(b"A" * i)
        new_length = len(oracle(data))
        block_size = new_length - known_length
        if block_size:
            return block_size
        i += 1

def get_unknown_string_size(oracle):
    known_length = len(oracle(b''))
    i = 1
    while True:
        data = bytearray(b"A" * i)
        new_length = len(oracle(data))
        if known_length != new_length:
            return known_length - i
        i += 1
        
def create_admin_account():
    block_size = get_block_size(profile_for)
    
    # Align the data into blocks so that 'user' will be on a new block
    required_bytes = len("email=@gmail.com&uid=10&role=")
    prefix_bytes = (required_bytes // block_size + 1) * block_size
    remaining_bytes = prefix_bytes - required_bytes

    email = b"a" * remaining_bytes + b"@gmail.com"
    # Snip out the blocks containing all the data before the role data
    profile_prefix = profile_for(email)[:prefix_bytes]

    # Align the data into blocks so 'admin' will be on its own block with the correct padding
    required_bytes = len("email=@gmail.com")
    suffix_bytes = (required_bytes // block_size + 1) * block_size
    remaining_bytes = suffix_bytes - required_bytes

    email = b"a" * remaining_bytes +  b"@gmail.com"
    admin_pos = required_bytes + remaining_bytes
    # Snip out the block containing 'admin', correctly padded
    profile_suffix = profile_for(email + cpt.pcks7pad(b'admin'))[admin_pos:admin_pos + block_size] #

    print(dec_profile(profile_prefix + profile_suffix))

create_admin_account()