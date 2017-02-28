#!/usr/bin/env python3
# coding: utf-8

"""
CBC bitflipping attacks.
https://cryptopals.com/sets/2/challenges/16
"""

import os
import urllib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from xor import xor
from block import pkcs7_pad, pkcs7_unpad, cbc_encrypt, cbc_decrypt

KEYSIZE = 16

k = os.urandom(KEYSIZE)
iv = os.urandom(16)


def encrypt(p):
    p = ('comment1=cooking%20MCs;userdata=' +
         urllib.parse.quote(p, safe='') +
         ';comment2=%20like%20a%20pound%20of%20bacon')
    p = bytes(p, 'utf8')
    return cbc_encrypt(pkcs7_pad(p, 16), k, iv)


def decrypt_and_verify(e):
    p = pkcs7_unpad(cbc_decrypt(e, k, iv))
    return p.find(b';admin=true;') != -1


def flip(e, current_string, desired_string, off):
    e = list(e)
    for i in range(0, len(desired_string)):
        e[off + i] ^= current_string[i] ^ desired_string[i]
    return bytes(e)

e = encrypt('AAAAAAAAAAAAAAAA;admin=true;AAAA')
e = flip(e, b'%3Badmin%3Dtrue%', b'AA;admin=true;AA', 32)

print(decrypt_and_verify(e))
