#! /usr/bin/python3

# https://www.cryptopals.com/sets/5/challenges/39
# Implement RSA

import sys 
sys.path.append('..')

from cryptopals import int_to_bytes,modinv,rsa_encrypt,rsa_decrypt,rsa_key_gen,test_primes,generate_rsa_prime

# "Testing"
p = 5
q = 17
e = 3

pub_key, priv_key = rsa_key_gen(p,q,e)

e = pub_key[0]
n = pub_key[1]
d = priv_key[0]
m = 42
print(rsa_decrypt(rsa_encrypt(m,e,n),d,n))

# "Serious stuff"
e = 3
p = generate_rsa_prime()
q = generate_rsa_prime()

while (test_primes(p,q,e) != True):
    p = generate_rsa_prime()
    q = generate_rsa_prime()

pub_key, priv_key = rsa_key_gen(p,q,e)

message = b"This is a super S3cr3t message!!!!"

m = int.from_bytes(message, byteorder='big')
e = pub_key[0]
n = pub_key[1]
d = priv_key[0]

c = rsa_encrypt(m,e,n)
decrypted_int = rsa_decrypt(c,d,n)
decrypted = int_to_bytes(decrypted_int,order="big")
print(decrypted)

