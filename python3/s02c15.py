#!/usr/bin/env python3
# coding: utf-8

"""
PKCS#7 padding validation.
https://cryptopals.com/sets/2/challenges/15
"""

from block import pkcs7_unpad


def validate_pkcs7(bs):
    try:
        pkcs7_unpad(bs)
        print("{0} has valid padding".format(bs))
    except Exception as e:
        print("{0} has invalid padding".format(bs))

validate_pkcs7(b'ICE ICE BABY\x04\x04\x04\x04')
validate_pkcs7(b'ICE ICE BABY\x05\x05\x05\x05')
validate_pkcs7(b'ICE ICE BABY\x01\x02\x03\x04')
