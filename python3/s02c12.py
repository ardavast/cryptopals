#!/usr/bin/env python3
# coding: utf-8

"""
Byte-at-a-time ECB decryption (Simple).
https://cryptopals.com/sets/2/challenges/12
"""

import os
from base64 import b64decode

from block import pkcs7_pad, ecb_encrypt, ecb_detect

KEYSIZE = 16

cb64s = ('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBj'
         'YW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBo'
         'aQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
k = os.urandom(KEYSIZE)

c = b64decode(cb64s)


def encryption_oracle(p):
    return ecb_encrypt(pkcs7_pad(p + c, 16), k)


def guess_blocksize():
    csize0 = len(encryption_oracle(b''))
    psize = 1
    while True:
        p = b'X' * psize
        csize = len(encryption_oracle(p))
        if csize - csize0 > 0:
            return csize - csize0
        psize += 1


def ecb_crack_block(blocksize, p):
    target_bytes = slice(len(p), len(p) + blocksize)
    pblock = b''
    for i in range(1, blocksize + 1):
        crafted_block = b'X' * (blocksize - i)
        c0 = encryption_oracle(crafted_block)
        for b in range(255 + 1):
            b = bytes([b])
            c = encryption_oracle(crafted_block + p + pblock + b)
            if c[target_bytes] == c0[target_bytes]:
                pblock += b
                break
    return pblock


blocksize = guess_blocksize()
if ecb_detect(encryption_oracle(b'X' * blocksize * 2)):
    p = b''
    for i in range(len(encryption_oracle(b'')) // blocksize):
        p += ecb_crack_block(blocksize, p)
    p = p[:-1]
    print(p.decode('utf8'))
