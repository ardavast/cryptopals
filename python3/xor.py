# coding: utf-8

"""Helper functions for using XOR/Vigenère ciphers."""

from itertools import cycle

def xor(bs1, bs2):
    """XOR the bytes-like objects bs1 and bs2.
    If one of the objects is larger in size it will be XORed against repeating
    copies of the smaller object.
    """
    if len(bs1) < len(bs2):
        (bs1, bs2) = (bs2, bs1)

    return bytes([b1 ^ b2 for (b1, b2) in zip(bs1, cycle(bs2))])
