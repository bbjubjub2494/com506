# This is Cameron Hochberg's solution
# https://susanou.github.io/Writeups/posts/pythia/

import time

from base64 import b64encode, b64decode
from pwn import *
from bitstring import BitArray
from string import ascii_lowercase
from itertools import product
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from Crypto.Util.number import bytes_to_long, long_to_bytes

F.<X> = GF(2)[]
G.<x> = GF(2^128, modulus=X^128 + X^7 + X^2 + X + 1)
K.<y> = G[]

passwords = []

# passwords = [''.join(letters).encode() for letters in list(product(ascii_lowercase, repeat=3))]
for i in string.ascii_lowercase:
    for j in string.ascii_lowercase:
        for k in string.ascii_lowercase:
            passwords.append(i+j+k)

keys = []
for pw in passwords:
    #print(pw)
    kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1, backend=default_backend())
    key = kdf.derive(pw.encode())
    #print(key)
    keys.append(key)



def bytes_to_elt(in_bytes):
    return G([int(v) for v in BitArray(in_bytes).bin])


def collide(keys, nonce, tag):
    L_bytes = long_to_bytes(len(keys) * 128)
    L_bytes = bytes([0]) * (16 - len(L_bytes)) + L_bytes
    L = bytes_to_elt(L_bytes)
    T = bytes_to_elt(tag)
    pairs = []

    for key in keys:
        # print(key)
        # print(type(key))
        H_cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        H_encryptor = H_cipher.encryptor()
        H_bytes = H_encryptor.update(bytes([0]) * 16) + H_encryptor.finalize()
        H = bytes_to_elt(H_bytes)

        P_cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        P_encryptor = P_cipher.encryptor()
        P_bytes = P_encryptor.update(nonce + bytes([0]) * 3 + bytes([1])) + P_encryptor.finalize()
        P = bytes_to_elt(P_bytes)

        y = ((L * H) + P + T) * H^(-2)
        pairs.append((H, y))

    coeffs = K.lagrange_polynomial(pairs).list()

    ciphertext = b''
    for coeff in coeffs[::-1]:
        cc = coeff.polynomial().list()
        cc += [0] * (128 - len(cc))
        ciphertext += BitArray(cc).bytes

    ciphertext += bytes([0]) * 16  # tag at end

    return ciphertext

# test it works

""" ciphertext = collide(keys[:3], bytes([0]) * 12, bytes([0]) * 16)
print(f"[+] CT created: {ciphertext}")
cipher = AESGCM(keys[0])
plaintext = cipher.decrypt(bytes([0]) * 12, ciphertext, associated_data=None)
print(f"[*]  decrypted PT: {plaintext}") """

print(len(keys))
#print(passwords[0])

# ciphertext = collide(keys[:3], bytes([0]) * 12, bytes([0])*16)

# print(b64encode(b'0'*12)+b','+b64encode(ciphertext))


def binary_search(start, end):

    pivot = (start + end) // 2

    if start == pivot:
        print(f'[+] Creating collision ciphertext of slice keys[{start}]')
        print(f"key type = {type(keys[start])}")
        ciphertext = collide([keys[start]], bytes([0]) * 12, bytes([0])*16)
        print(f'[->] Sending cipher text of slice keys[{start}]')
        conn.sendline(b'3')
        conn.recvuntil(b'>>> ')
        conn.sendline(b64encode(bytes([0]) * 12)+b','+b64encode(ciphertext))
        response = conn.recvuntil(b'>>> ')

        if b'ERROR: Decryption failed. Key was not correct' not in response:
            print(f"[+] FOUND KEY: {passwords[start]}")
            return start
        else:

            print(f"[+] FOUND KEY: {passwords[end]}")
            return end


    print(f'[+] Creating collision ciphertext of slice keys[{start}:{pivot}]')
    ciphertext = collide(keys[start:pivot], bytes([0]) * 12, bytes([0])*16)
    print(f'[->] Sending cipher text of slice keys[{start}:{pivot}]')
    conn.sendline(b'3')
    conn.recvuntil(b'>>> ')
    conn.sendline(b64encode(bytes([0]) * 12)+b','+b64encode(ciphertext))
    response = conn.recvuntil(b'>>> ')

    if b'ERROR: Decryption failed. Key was not correct' not in response:
        return binary_search(start, pivot)
    else:
        return binary_search(pivot, end)

#context.log_level = 'debug'
conn = remote('pythia.2021.ctfcompetition.com', 1337)


with open('ciphers.p', 'rb') as f:
    ciphers = pickle.load(f)

key_list = []

conn.recvuntil(b'>>> ')
for j in range(3):
    print(f'[+] Setting key to {j}')
    conn.sendline(b'1')
    conn.recvuntil(b'>>> ')
    conn.sendline(str(j).encode())
    conn.recvuntil(b'>>> ')

    for i in range(0, len(keys), 1000):
        print(f'[+] Creating collision ciphertext of slice keys[{i}:{i+1000}]')
        ciphertext = ciphers[i // 1000] # collide(keys[i:i+1000], bytes([0]) * 12, bytes([0])*16)
        print(f'[->] Sending cipher text of slice keys[{i}:{i+1000}]')
        conn.sendline(b'3')
        conn.recvuntil(b'>>> ')
        conn.sendline(b64encode(bytes([0]) * 12)+b','+b64encode(ciphertext))
        response = conn.recvuntil(b'>>> ')
        print(response)
        if b'ERROR: Decryption failed. Key was not correct' not in response:
            key_list.append(passwords[binary_search(i, i+1000)].encode('utf-8'))
            break

if len(key_list) == 3:
    conn.sendline(b'2')
    conn.recvuntil(b'>>> ')
    conn.sendline(b''.join(key_list))
    stuff = conn.recvuntil(b'>>> ')
    print(stuff)

