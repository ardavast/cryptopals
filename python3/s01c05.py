#!/usr/bin/env python3
# coding: utf-8

"""
Implement repeating-key XOR.
https://cryptopals.com/sets/1/challenges/5
"""

from binascii import hexlify
from xor import xor

ps = ("Burning 'em, if you ain't quick and nimble\n"
      "I go crazy when I hear a cymbal")
ks = 'ICE'

p = bytes(ps, 'utf8')
k = bytes(ks, 'utf8')

e = xor(p, k)

print(hexlify(e).decode('utf8'))
