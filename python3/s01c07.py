#!/usr/bin/env python3
# coding: utf-8

"""
AES in ECB mode.
https://cryptopals.com/sets/1/challenges/7
"""

from base64 import b64decode

from block import pkcs7_unpad, ecb_decrypt


with open('s01c07.txt', 'r') as f:
    c = b64decode(f.read())
    k = b'YELLOW SUBMARINE'

    p = pkcs7_unpad(ecb_decrypt(c, k))
    print(p.decode('utf8'))
