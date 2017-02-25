from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pkcs7_unpad(s):
    psize = s[-1]
    if psize == 0 or s[-psize:] != bytes([psize]) * psize:
        raise ValueError
    return s[:-psize]

def ecb_decrypt(c, k):
    decryptor = Cipher(algorithms.AES(k), modes.ECB(), default_backend())
    decryptor = decryptor.decryptor()
    return decryptor.update(c) + decryptor.finalize()
