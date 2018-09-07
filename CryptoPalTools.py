import base64

def xor(b1, b2):
    b = bytearray(len(b1))
    for i in range(len(b1)):
        b[i] = b1[i] ^ b2[i]
    return b

def score_text(s):
    freq = {}
    freq[' '] = 5.700000000
    freq['e'] = 5.390395169
    freq['t'] = 5.282039486
    freq['a'] = 5.248362256
    freq['o'] = 5.235661502
    freq['i'] = 5.214822972
    freq['n'] = 5.214319386
    freq['s'] = 5.196844692
    freq['h'] = 5.193607737
    freq['r'] = 5.184990759
    freq['d'] = 5.134044565
    freq['l'] = 5.125951672
    freq['u'] = 5.88219598
    freq['c'] = 5.79962026
    freq['m'] = 5.79502870
    freq['f'] = 5.72967175
    freq['w'] = 5.69069021
    freq['g'] = 5.61549736
    freq['y'] = 5.59010696
    freq['p'] = 5.55746578
    freq['b'] = 5.47673928
    freq['v'] = 5.30476191
    freq['k'] = 5.22969448
    freq['x'] = 5.5574077
    freq['j'] = 5.4507165
    freq['q'] = 5.3649838
    freq['z'] = 5.2456495
    score = 0
    for c in s.lower():
        if c in freq:
            score += freq[c]
    return score

def solve_single_key_xor(ba):
    res = []
    for i in range(256):
        txt = ''.join([chr(c ^ i) for c in ba])
        res.append((score_text(txt), txt, i))
    return max(res, key=lambda x: x[0])[2]

def repeating_key_xor(plaintext, key):
    ba = bytearray(plaintext)
    keyba = bytearray(key)
    for i in range(len(ba)):
        ba[i] = ba[i] ^ keyba[i % len(keyba)]
    return ba

def pcks7pad(ba, length=16):
    pad_length = length - len(ba) % length
    ba += bytearray(chr(pad_length).encode() * pad_length)
    return ba

def pcks7unpad(b, length=16):
    ba = bytearray(b)
    padding = ba[-1]
    for i in range(len(ba) - 1, len(ba) - padding, -1):
        if ba[i] != ba[i - 1]:
            raise Exception("Invalid PCKS#7 padding scheme")
    return ba[:-padding]

def read_base64_file(filename):
    with open(filename, 'rb') as file:
        d = base64.b64decode(bytearray(file.read()).replace(b'\r\n', b''))
    return d

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