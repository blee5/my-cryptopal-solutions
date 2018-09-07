import AES
import os
import random
import CryptoPalTools as cpt

key = bytearray(os.urandom(16))
prefix = os.urandom(random.randint(1, 30000))

def ecb_encryptor(plaintext):
    unknown_string = b"My mom told me that life is like a box of chocolate. I hate chocolate."
    plaintext = prefix + plaintext + unknown_string
    return AES.aes_128_ecb_enc(plaintext, key)

def get_unknown_string_size(oracle, prefix_size):
    known_length = len(oracle(b''))
    i = 1
    while True:
        data = bytearray(b"A" * i)
        new_length = len(oracle(data))
        if known_length != new_length: 
            return known_length - i - prefix_size
        i += 1

def get_prefix_size(oracle, block_size):
    # NOTE: only works with ECB
    for prepad_length in range(block_size):
        reps = 5
        test_input = b"#" * prepad_length + b'YELLOW SUBMARINE' * reps
        ba = oracle(test_input)
        prev_block = found_count = None

        for i in range(0, len(ba), block_size):
            block = ba[i: i + block_size]
            if block == prev_block:
                found_count += 1
            else:
                first_block_index = i
                found_count = 1
                prev_block = block

            if found_count == reps:
                return first_block_index - prepad_length

def main():
    block_size = cpt.get_block_size(ecb_encryptor)
    prefix_size = get_prefix_size(ecb_encryptor, block_size)
    string_size = get_unknown_string_size(ecb_encryptor, prefix_size)

    num_blocks = (string_size + prefix_size) // block_size + 1
    input_block = bytearray(b'@' * (block_size * num_blocks - 1 - prefix_size))
    last_block_pos = (num_blocks - 1) * block_size

    ba = bytearray()

    for i in range(string_size):
        cipher_results = {}

        for byte in range(256):
            temp = ecb_encryptor(input_block + ba + bytes([byte]))
            cipher_results[bytes([byte])] = temp[last_block_pos:last_block_pos + block_size]
        temp = ecb_encryptor(input_block)
        
        for byte, block in cipher_results.items():
            if block == temp[last_block_pos:last_block_pos + block_size]:
                ba += byte
                break

        input_block = input_block[:-1]

    print(ba.decode())

main()