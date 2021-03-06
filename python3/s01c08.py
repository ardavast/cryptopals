#!/usr/bin/env python3
# coding: utf-8

"""
Detect AES in ECB mode.
https://cryptopals.com/sets/1/challenges/8
"""

from binascii import unhexlify

from block import ecb_detect

with open('s01c08.txt', 'r') as f:
    for line in f:
        chs = line.rstrip('\n')
        c = unhexlify(chs)
        if ecb_detect(c):
            print(chs)
