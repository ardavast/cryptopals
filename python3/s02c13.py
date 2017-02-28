#!/usr/bin/env python3
# coding: utf-8

"""
ECB cut-and-paste.
https://cryptopals.com/sets/2/challenges/13
"""

import os
import json
import urllib

from block import pkcs7_pad, pkcs7_unpad, ecb_encrypt, ecb_decrypt

KEYSIZE = 16

k = os.urandom(KEYSIZE)


def kv_parse(qs):
    urldict = {}
    urldict0 = urllib.parse.parse_qs(qs)
    for (key, value) in urldict0.items():
        urldict[key] = value
    return json.dumps(urldict)


def profile_for(email):
    email = urllib.parse.quote(email, safe='@')
    p = bytes('email=' + email + '&uid=10&role=user', 'utf8')
    return(ecb_encrypt(pkcs7_pad(p, 16), k))


def decrypt_profile(c):
    p = pkcs7_unpad(ecb_decrypt(c, k))
    return kv_parse(p.decode('utf8'))

c1 = profile_for(b'userXXXXXXXXXXXXXX@domain.com')
c2 = profile_for(b'X@XXXX.comadmin')
c3 = profile_for(b'X@XXX.com')
c = c1[0:48] + c2[16:32] + c3[-16:]
print(decrypt_profile(c))
