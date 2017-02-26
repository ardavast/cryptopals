# coding: utf-8

"""Helper functions for using block ciphers."""

from collections import Counter

from more_itertools import chunked
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from xor import xor


def pkcs7_pad(s, psize):
    pad = psize - (len(s) % psize)
    return s + bytes([pad]) * pad


def pkcs7_unpad(s):
    psize = s[-1]
    if psize == 0 or s[-psize:] != bytes([psize]) * psize:
        raise ValueError
    return s[:-psize]


def ecb_encrypt(p, k):
    if len(p) % 16 != 0 or len(k) not in (16, 24, 32):
        raise ValueError
    encryptor = Cipher(algorithms.AES(k), modes.ECB(), default_backend())
    encryptor = encryptor.encryptor()
    return encryptor.update(p) + encryptor.finalize()


def ecb_decrypt(c, k):
    if len(c) % 16 != 0 or len(k) not in (16, 24, 32):
        raise ValueError
    decryptor = Cipher(algorithms.AES(k), modes.ECB(), default_backend())
    decryptor = decryptor.decryptor()
    return decryptor.update(c) + decryptor.finalize()


def ecb_detect(c):
    if len(c) % 16 != 0:
        raise ValueError
    cblocks = [bytes(cblock) for cblock in chunked(c, 16)]
    [(pattern, count)] = Counter(cblocks).most_common(1)
    return count > 1


def cbc_encrypt(p, k, iv):
    if len(p) % 16 != 0 or len(k) not in (16, 24, 32) or len(iv) != 16:
        raise ValueError
    c = b''
    prev_cblock = iv
    for pblock in chunked(p, 16):
        pblock = bytes(pblock)
        cblock = ecb_encrypt(xor(pblock, prev_cblock), k)
        prev_cblock = cblock
        c += cblock
    return c


def cbc_decrypt(c, k, iv):
    if len(c) % 16 != 0 or len(k) not in (16, 24, 32) or len(iv) != 16:
        raise ValueError
    p = b''
    prev_cblock = iv
    for cblock in chunked(c, 16):
        cblock = bytes(cblock)
        pblock = xor(ecb_decrypt(cblock, k), prev_cblock)
        prev_cblock = cblock
        p += pblock
    return p
