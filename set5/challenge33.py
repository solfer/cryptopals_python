#! /usr/bin/python

# https://www.cryptopals.com/sets/5/challenges/33
# Implement Diffie-Hellman

from random import randint

p = 37
g = 5

a = randint(0,p)
A = (g ** a) % p

b = randint(0,p)
B = (g ** b) % p

s = (B ** a) % p
s2 = (A ** b) % p

if s == s2:
    print "Success!"


p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2


a = randint(0,p)
A = pow(g, a, p)

b = randint(0,p)
B = pow(g, b, p)

s = pow(B, a, p)
s2 = pow(A, b, p)


if s == s2:
    print "Success!"


