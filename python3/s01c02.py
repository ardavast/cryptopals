#!/usr/bin/env python3
# coding: utf-8

"""
Fixed XOR.
https://cryptopals.com/sets/1/challenges/2
"""

from binascii import hexlify, unhexlify
from xor import xor

hs1 = '1c0111001f010100061a024b53535009181c'
hs2 = '686974207468652062756c6c277320657965'

bs1 = unhexlify(hs1)
bs2 = unhexlify(hs2)

bs3 = xor(bs1, bs2)

print(hexlify(bs3).decode('utf8'))
