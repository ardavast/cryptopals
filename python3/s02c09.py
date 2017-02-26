#!/usr/bin/env python3
# coding: utf-8

"""
Implement PKCS#7 padding.
https://cryptopals.com/sets/2/challenges/9
"""

from block import pkcs7_pad

bs = b'YELLOW SUBMARINE'

print(pkcs7_pad(bs, 20))
