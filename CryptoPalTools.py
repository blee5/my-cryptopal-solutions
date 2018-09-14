import base64

def xor(b1, b2):
    b = bytearray(len(b1))
    for i in range(len(b1)):
        b[i] = b1[i] ^ b2[i]
    return b

# source: https://gist.github.com/mikeecb/0d75f46521fe526a0138ae5265392505
# TODO: store frequencies in a file and read it instead of this mess
def score_text(s):
    freq = {}
    freq[' '] = 700000000
    freq['e'] = 390395169
    freq['t'] = 282039486
    freq['a'] = 248362256
    freq['o'] = 235661502
    freq['i'] = 214822972
    freq['n'] = 214319386
    freq['s'] = 196844692
    freq['h'] = 193607737
    freq['r'] = 184990759
    freq['d'] = 134044565
    freq['l'] = 125951672
    freq['u'] = 88219598
    freq['c'] = 79962026
    freq['m'] = 79502870
    freq['f'] = 72967175
    freq['w'] = 69069021
    freq['g'] = 61549736
    freq['y'] = 59010696
    freq['p'] = 55746578
    freq['b'] = 47673928
    freq['v'] = 30476191
    freq['k'] = 22969448
    freq['x'] = 5574077
    freq['j'] = 4507165
    freq['q'] = 3649838
    freq['z'] = 2456495
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
