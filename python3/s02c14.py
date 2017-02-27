#!/usr/bin/env python3
# coding: utf-8

"""
Byte-at-a-time ECB decryption (Harder).
https://cryptopals.com/sets/2/challenges/14
"""

import os
from collections import Counter
from random import randint
from base64 import b64decode

from more_itertools import chunked

from block import pkcs7_pad, ecb_encrypt, ecb_detect

PREFIX_MIN_SIZE = 0
PREFIX_MAX_SIZE = 128
KEYSIZE = 16

prefix = os.urandom(randint(PREFIX_MIN_SIZE, PREFIX_MAX_SIZE))
print(prefix)
cb64s = ('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBj'
         'YW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBo'
         'aQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
k = os.urandom(KEYSIZE)

c = b64decode(cb64s)


def encryption_oracle(p):
    return ecb_encrypt(pkcs7_pad(prefix + p + c, 16), k)


def guess_blocksize():
    csize0 = len(encryption_oracle(b''))
    psize = 1
    while True:
        p = b'X' * psize
        csize = len(encryption_oracle(p))
        if csize - csize0 > 0:
            return (csize - csize0)
        psize += 1


def ecb_crack_block(blocksize, p, pprefix, byte, position):
    target_bytes = slice(position * blocksize + len(p),
                         position * blocksize + len(p) + blocksize)
    pblock = b''
    for i in range(1, blocksize + 1):
        crafted_block = pprefix + byte * (blocksize - i)
        c0 = encryption_oracle(crafted_block)
        for b in range(0, 255 + 1):
            b = bytes([b])
            c = encryption_oracle(crafted_block + p + pblock + b)
            if c[target_bytes] == c0[target_bytes]:
                pblock += b
                break
    return pblock


def guess_position():
    def test_byte(byte):
        c0 = encryption_oracle(b'')
        cblocks = [bytes(cblock) for cblock in chunked(c0, 16)]
        [(_, count)] = Counter(cblocks).most_common(1)

        c = encryption_oracle(byte * (16 * (count + 2)))
        cblocks = [bytes(cblock) for cblock in chunked(c, 16)]
        [(pattern, count)] = Counter(cblocks).most_common(1)
        positions = [i for i, p in enumerate(cblocks) if p == pattern]
        return (pattern, positions)

    (_, xpos) = test_byte(b'X')
    (_, ypos) = test_byte(b'Y')
    if xpos == ypos:
        byte = b'X'
    else:
        byte = b'Z'
    (cpattern, cpos) = test_byte(byte)

    psize = 1
    while True:
        p = byte * psize
        c = encryption_oracle(p)
        cblocks = [bytes(cblock) for cblock in chunked(c, 16)]
        if cpattern in cblocks:
            break
        psize += 1
    return byte, psize % 16, cblocks.index(cpattern)

blocksize = guess_blocksize()
if ecb_detect(encryption_oracle(b'X' * blocksize * 3)):
    byte, psize, position = guess_position()
    pprefix = byte * (psize)
    p = b''
    for i in range(len(encryption_oracle(b'')) // blocksize):
        p += ecb_crack_block(blocksize, p, pprefix, byte, position)
    p = p[:-1]
    print(p.decode('utf8'))
