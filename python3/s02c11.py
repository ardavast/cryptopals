#!/usr/bin/env python3
# coding: utf-8

"""
An ECB/CBC detection oracle.
https://cryptopals.com/sets/2/challenges/11
"""

import os
from random import randint, choice

from block import pkcs7_pad, ecb_encrypt, cbc_encrypt, ecb_detect

KEYSIZE = 16


def encryption_oracle(p):
    p = os.urandom(randint(5, 5)) + p + os.urandom(randint(5, 10))
    k = os.urandom(KEYSIZE)

    mode = choice(['ECB', 'CBC'])
    print("Encrypting under {0} mode".format(mode))
    if mode == 'ECB':
        return ecb_encrypt(pkcs7_pad(p, 16), k)
    if mode == 'CBC':
        iv = os.urandom(16)
        return cbc_encrypt(pkcs7_pad(p, 16), k, iv)

p = b'X' * 43  # 2 * 16 + (16 - 5)
c = encryption_oracle(p)

print("ECB detected: {0}".format(ecb_detect(c)))
