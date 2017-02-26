#!/usr/bin/env python3
# coding: utf-8

"""
Implement CBC mode.
https://cryptopals.com/sets/2/challenges/10
"""

from base64 import b64decode

from block import pkcs7_unpad, cbc_decrypt


with open('s02c10.txt', 'r') as f:
    c = b64decode(f.read())
    k = b'YELLOW SUBMARINE'
    iv = b'\x00' * 16

    p = pkcs7_unpad(cbc_decrypt(c, k, iv))
    print(p.decode('utf8'))
