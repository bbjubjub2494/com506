# Introduction
Who are we?

What are partitioning oracles? new class of key-recovery attacks on authenticated encryption.

This is the introduction btw

Outline

# Quick reminder on AEAD
safe all-in-one combination of ciphertext and MAC.

Currently used variants: AES-GCM, AES-GCM-SIV, XSalsa20/Poly1305, and ChaCha20/Poly1305. (?)

# key guessing
Baseline: random key guessing game, online attack (COM401 notes p. 54) unavoidable. Amount of guesses: O(#K) <= O(exp(lambda))
known non-uniform distribution -> easier for the adversary

# The Attack
Idea: craft ciphertext that will authenticate for more than one key. Similar oracle than earlier. Key guessing can be exponentially faster.

*insert formulas*

Difficulty: generate a key multi-collision. Depends on the scheme. Example: AES-GCM polynomial interpolation.

# Defenses
ciphers should be (T)MKCR. *insert games*

Poly1305: breaks the algebraic structure

#example: shadowsocks pasword recovery

#demo: Pythia
There was a challenge based on that attack in Google CTF 2021. We can run that and show it.
https://ctftime.org/writeup/29330

# Citations
Partitioning oracle attacks https://eprint.iacr.org/2020/1491.pdf
