# coding: utf-8

"""Helper functions for using block ciphers."""

from collections import Counter

from more_itertools import chunked
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def pkcs7_pad(s, psize):
    pad = psize - (len(s) % psize)
    return s + bytes([pad]) * pad


def pkcs7_unpad(s):
    psize = s[-1]
    if psize == 0 or s[-psize:] != bytes([psize]) * psize:
        raise ValueError
    return s[:-psize]


def ecb_decrypt(c, k):
    decryptor = Cipher(algorithms.AES(k), modes.ECB(), default_backend())
    decryptor = decryptor.decryptor()
    return decryptor.update(c) + decryptor.finalize()


def ecb_detect(c):
    if len(c) % 16 != 0:
        raise ValueError
    cblocks = [bytes(cblock) for cblock in chunked(c, 16)]
    [(pattern, count)] = Counter(cblocks).most_common(1)
    return count > 1
