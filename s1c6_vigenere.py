# TODO: BREAK FIXED KEY XOR

import base64
import os
import CryptoPalTools as cpt

def hammingdistance(a, b):
    differing_bits = 0
    for byte in cpt.xor(a, b):
        differing_bits += bin(byte).count("1")
    return differing_bits

def chunks(l, n):
    data = []
    for i in range(0, len(l), n):
        data.append(l[i:i+n])
    return data

def break_repeating_key_xor(data):
    dists = []

    for n in range(2, 31):
        b1 = data[:n]
        b2 = data[n:2*n]
        b3 = data[2*n:3*n]
        b4 = data[3*n:4*n]
        normalized_distance = (hammingdistance(b1, b2) + hammingdistance(b2, b3) + hammingdistance(b3, b4)) / n

        dists.append((n, normalized_distance))

    dists = sorted(dists, key=lambda x: x[1])

    keylist = []
    for keysize, _ in dists[:5]:
        key = bytearray()
        blocks = chunks(data, keysize)
        for i in range(keysize):
            temp = b''
            for block in blocks:
                if i < len(block):
                    temp += bytes([block[i]])
            key.append(cpt.solve_single_key_xor(bytearray(temp)))
        keylist.append(key)
    return keylist
            
plaintext = b"""Hello, this is a test string. I hope you can break this thing and read this. 
Maybe in the future, humanity will ascend... I sure hope that X-rays will become illegal and we will be able to ride zebras
at zoos in peace without getting assassinated by PETA. Maybe that's too idealistic? I don't really know what to write here.
Perhaps I should write some song lyrics!
Here we go:
\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01
Somebody once told me that the world was gonna roll me, I ain't the sharpest tool in the shed.
She was looking kind of funny with her finger in the shape of an L on her forehead.
Well, the years start coming and they don't stop coming,
Fed to the rules and I hit the ground running!
Didn't make sense not to live for fun, your brain gets smart but your head gets dumb.
How many shrimps can you eat, before your skins turn pink??
I don't actually know the lyrics to that one haha
\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01
Oh by the way
You probably notieced there is a bug with this code. If the plaintext is too short it goes out of bounds
when calculating the Hamming distance for possible key lengths. I'm too lazy to fix that.

Sad! Anyways, good bye."""

key = b"A Moon Shaped Pool"

ciphertext = cpt.repeating_key_xor(plaintext, key)

keylist = break_repeating_key_xor(ciphertext)

for key in keylist:
    t = cpt.repeating_key_xor(ciphertext, key)
    try:
        t = t.decode()
        print(key, ':' , cpt.score_text(t), '\n', t, '\n')
    except:
        pass