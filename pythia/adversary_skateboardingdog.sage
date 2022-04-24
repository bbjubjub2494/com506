# This is Joseph Surin's solution
# https://jsur.in/posts/2021-07-19-google-ctf-2021-crypto-writeups#pythia

import os, time
os.environ['PWNLIB_NOTERM'] = 'True'
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from string import ascii_lowercase
from itertools import product
from base64 import b64encode
from pwn import remote, process, context
from tqdm import tqdm

ORDERED_PASSWORDS = []
POSSIBLE_KEYS = {}
for a,b,c in product(ascii_lowercase, repeat=3):
    kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1, backend=default_backend())
    key = kdf.derive(bytes(a+b+c, 'UTF-8'))
    ORDERED_PASSWORDS.append(a+b+c)
    POSSIBLE_KEYS[a+b+c] = key

NONCE = b'\x55'*12
TAG = b'\x66'*16
F2.<x> = GF(2)[]
p = x^128 + x^7  + x^2 + x + 1
F = GF(2^128, 'x', modulus=p, impl='pari_ffelt')
R.<z> = PolynomialRing(F)

def block_aes(block, key):
    return AES.new(key, AES.MODE_CBC, iv=b'\x00'*16).encrypt(block)

# https://github.com/kste/keycommitment/blob/main/util.sage
def bytes_to_F(block):
    field_element = 0
    for i in range(128):
        if (block[i // 8] >> (7 - (i % 8))) & 1 == 1:
            field_element += x^i
    return F(field_element)

def F_to_bytes(element):
    coeff = element.polynomial().coefficients(sparse=False)
    result = [0 for _ in range(16)]
    for i in range(len(coeff)):
        if coeff[i] == 1:
            result[i // 8] |= (1 << ((7 - i) % 8))
    return bytes(result)

def attack(keys, nonce, tag):
    L = bytes_to_F(b'\x00' * 8 + long_to_bytes(128 * len(keys), 8))
    N = nonce + b'\x00'*3 + b'\x01'
    T = bytes_to_F(tag)
    interpolation_pts = []
    for key in keys:
        H = bytes_to_F(block_aes(b'\x00'*16, key))
        B = ((L * H) + bytes_to_F(block_aes(N, key)) + T) * H^-2
        interpolation_pts.append((H, B))
    start = time.time()
    sol = R.lagrange_polynomial(interpolation_pts)
    t = time.time() - start
    print(f'polynomial interpolation took {t}s')
    C_blocks = [F_to_bytes(c) for c in sol.coefficients(sparse=False)[::-1]]
    return b''.join(C_blocks)

def get_ciphertexts(CHUNK_SIZE, outdir):
    key_chunks = [ORDERED_PASSWORDS[i:i+CHUNK_SIZE] for i in range(0, len(ORDERED_PASSWORDS), CHUNK_SIZE)]
    s = sum(len(kc) for kc in key_chunks)
    if s < 26^3:
        key_chunks += [ORDERED_PASSWORDS[s:]]

    i = 0
    for keys in key_chunks:
        keys = [POSSIBLE_KEYS[pw] for pw in keys]
        import hashlib
        C = attack(keys, NONCE, TAG)
        print('C: ',hashlib.md5(C).hexdigest())
        l = str(i).zfill(5)
        open(f'{outdir}/{l}.dat', 'wb').write(C)
        i += len(keys)

        # sanity check; shouldn't throw an error
        aes = AES.new(keys[0], AES.MODE_GCM, nonce=NONCE)
        aes.decrypt_and_verify(C, TAG)

def oracle_decrypt(C):
    conn.sendlineafter('>>> ', '3')
    payload = b64encode(NONCE) + b',' + b64encode(C + TAG)
    conn.sendlineafter('>>> ', payload)
    conn.recvline()
    res = conn.recvline().decode()
    return 'success' in res

def solve_pw_rec(r):
    if r[1] - r[0] <= 1:
        return list(ORDERED_PASSWORDS)[r[0]]
    r1 = (r[0], (r[1]+r[0])//2)
    r2 = ((r[1]+r[0])//2, r[1])
    OP = ORDERED_PASSWORDS[r1[0]:r1[1]]
    PK = [POSSIBLE_KEYS[pw] for pw in OP]
    C = attack(PK, NONCE, TAG)
    if oracle_decrypt(C):
        return solve_pw_rec(r1)
    else:
        return solve_pw_rec(r2)

def solve_pw(idx, C1024, C512):
    conn.sendlineafter('>>> ', '1')
    conn.sendlineafter('>>> ', str(idx))

    # linear step through C1024
    LC1024 = list(C1024)
    for r in LC1024[:-1]:
        if oracle_decrypt(C1024[r]):
            break
    else:
        r = LC1024[-1]

    possible_C = {}
    for s in C512:
        if s[0] >= r[0] and s[1] <= r[1]:
            possible_C[s] = C512[s]
    assert len(possible_C) == 2
    r1, r2 = possible_C
    if oracle_decrypt(possible_C[r1]):
        return solve_pw_rec(r1)
    else:
        return solve_pw_rec(r2)

# get_ciphertexts(512, 'C512')
# get_ciphertexts(1024, 'C1024')

C1024 = {}
for f in os.listdir('./C1024'):
    l = int(f.strip('.dat'))
    r = (l, min(26^3, l + 1024))
    dat = open(f'./C1024/{f}', 'rb').read()
    C1024[r] = dat

C512 = {}
for f in os.listdir('./C512'):
    l = int(f.strip('.dat'))
    r = (l, min(26^3, l + 512))
    dat = open(f'./C512/{f}', 'rb').read()
    C512[r] = dat

conn = remote('pythia.2021.ctfcompetition.com', 1337)
pw0 = solve_pw(0, C1024, C512)
print('pw0 recovered:', pw0)
pw1 = solve_pw(1, C1024, C512)
print('pw1 recovered:', pw1)
pw2 = solve_pw(2, C1024, C512)
print('pw2 recovered:', pw2)
pw = pw0 + pw1 + pw2
print('password:', pw)
conn.sendlineafter('>>> ', '2')
conn.sendlineafter('>>> ', pw)
print(conn.recvline().decode())
print(conn.recvline().decode())
