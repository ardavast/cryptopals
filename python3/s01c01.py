#!/usr/bin/env python3
# coding: utf-8

"""
Convert hex to base64.
https://cryptopals.com/sets/1/challenges/1
"""

from binascii import unhexlify
from base64 import b64encode

hs = ('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6'
      'e6f7573206d757368726f6f6d')

bs = unhexlify(hs)
b64s = b64encode(bs)

print(b64s.decode('utf8'))
