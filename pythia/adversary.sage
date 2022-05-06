#!/usr/bin/env sage

# Based on Florian Picca's solution
# https://blog.oppida.apave.com/en/Nos-articles/Google-CTF-2021-Pythia

import pickle
import itertools
import string
import base64
from sage.all import *
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from pwn import *
import functools
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from bitstring import BitArray

P = PolynomialRing(GF(2), "x")
x = P.gen()
p = x ** 128 + x ** 7 + x ** 2 + x + 1
GH = GF(2 ** 128, "a", modulus=p)

def bytes_to_GH(data):
    """Simply convert bytes to field elements"""
    return GH([int(v) for v in BitArray(data).bin])

def GH_to_bytes(element):
    """Simply convert field elements to bytes"""
    return BitArray(element.polynomial().list()).tobytes().ljust(16, b'\x00')

def multi_collide_gcm(keyset, nonce, tag):
    R = PolynomialRing(GH, "r")
    L = bytes_to_GH(long_to_bytes(128 * len(keyset), 16))
    N = nonce + b'\x00\x00\x00\x01'
    T = bytes_to_GH(tag)
    interpolation_pts = []
    for key in keyset:
        H = bytes_to_GH(AES.new(key, AES.MODE_ECB).encrypt(b'\x00' * 16))
        B = ((L * H) + bytes_to_GH(AES.new(key, AES.MODE_ECB).encrypt(N)) + T) * H**-2
        interpolation_pts.append((H, B))
    sol = R.lagrange_polynomial(interpolation_pts)
    C_blocks = [GH_to_bytes(c) for c in sol.list()[::-1]]
    return b''.join(C_blocks) + tag

forge_precompute = {}
def forge(start, end):
    if (start, end) in forge_precompute:
        return forge_precompute[start, end]
    keyset = list(keys.keys())[start:end]
    r = multi_collide_gcm(keyset, b'\x00'*12, b'\x01'*16)
    return r

def setKey(i):
    conn.sendline(b"1")
    conn.recvuntil(b">>> ")
    conn.sendline(f"{i}".encode())
    conn.recvuntil(b">>> ")

def decrypt(c):
    conn.sendline(b"3")
    conn.recvuntil(b">>> ")
    t = f"{nonce.decode()},{base64.b64encode(c).decode()}"
    conn.sendline(t.encode())
    conn.recvline()
    r = conn.recvline()
    conn.recvuntil(b">>> ")
    if b"Decryption failed." in r:
        return False
    return True

def bsearch(start, end):
    global tries
    mid = (end + start)//2
    if end - start == 1:
        return start
    tries -= 1
    print(f"tries left : {tries}")
    if decrypt(forge(start, mid)):
        return bsearch(start, mid)
    else:
        return bsearch(mid, end)

    
if __name__ == "__main__":
    # build all keys and pickle them for next time
    try:
        keys = pickle.load(open("keys.pickle", "rb"))
    except FileNotFoundError:
        keys = {}
        for t in itertools.product(string.ascii_lowercase, repeat=3):
            pwd = "".join(t).encode()
            print(pwd)
            kdf = Scrypt(salt=b'', length=16, n=2 ** 4, r=8, p=1, backend=default_backend())
            keys[kdf.derive(pwd)] = pwd
        pickle.dump(keys, open("keys.pickle", "wb"))

    tries = 150
    N = 26**3
    B = 500
    nonce = base64.b64encode(b'\x00' * 12)

    try:
        forge_precompute = pickle.load(open("forge_precompute.pickle", "rb"))
    except FileNotFoundError:
        print("Precomputing...")
        for i in range(0, N, B):
            keyset = list(keys.keys())[i:i+B]
            forge_precompute[i, i+ B] = multi_collide_gcm(keyset, b'\x00'*12, b'\x01'*16)
        pickle.dump(forge_precompute, open("forge_precompute.pickle", "wb"))

    # recover the passwords and get the flag
    conn = remote("pythia.2021.ctfcompetition.com", 1337) if args.REMOTE else process("game.sage")
    conn.recvuntil(b">>> ")

    password = b''
    # 3 passwords in total
    for j in range(3):
        # search in chunks
        for i in range(0, N, B):
            # if key is in this chunk
            if decrypt(forge(i, i + B)):
                print("Entering binary search...")
                index = bsearch(i, i+B)
                pwd = keys[list(keys.keys())[index]]
                password += pwd
                print(f"Found password : {pwd}")
                break
            tries -= 1
            print(f"tries left : {tries}")
        if j < 2:
            setKey(j+1)
            tries -= 1
            print(f"tries left : {tries}")
    print(f"full password = {password.decode()}")
    conn.interactive()
    conn.close()

# vim: filetype=python:
