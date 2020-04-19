#! /usr/bin/python3

# https://www.cryptopals.com/sets/5/challenges/40
# Implement an E=3 RSA Broadcast attack

import sys 
sys.path.append('..')

from cryptopals import int_to_bytes,modinv,rsa_encrypt,rsa_decrypt,rsa_key_gen,test_primes,generate_rsa_prime

def precise_cube_root(x,precision=500):
    import decimal
    decimal.getcontext().prec = precision
    decimal.getcontext().rounding=decimal.ROUND_UP
    a = decimal.Decimal(x) ** decimal.Decimal(decimal.Decimal(1.0)/decimal.Decimal(3.))
    return a
# "Serious stuff"

e = 3
message = b"This is a super S3cr3t message!!!!"
#message = b"\x01"*100
m = int.from_bytes(message, byteorder='big')

#Generating 3 RSA keys
keys = []
for i in range(3):
    p = generate_rsa_prime()
    q = generate_rsa_prime()

    while (test_primes(p,q,e) != True):
        p = generate_rsa_prime()
        q = generate_rsa_prime()
    pub_key, priv_key = rsa_key_gen(p,q,e)
    keys.append((pub_key,priv_key))

#Encrypted the message using 3 different public keys
encrypted = []
for i in range(3):
    pub_key = keys[i][0]
    e = pub_key[0]
    n = pub_key[1]
    c = rsa_encrypt(m,e,n)
    encrypted.append(c)

n_0 = keys[0][0][1]
n_1 = keys[1][0][1]
n_2 = keys[2][0][1]

c_0 = encrypted[0] % n_0
c_1 = encrypted[1] % n_1
c_2 = encrypted[2] % n_2

m_s_0 = n_1 * n_2
m_s_1 = n_0 * n_2
m_s_2 = n_0 * n_1

N_012 = n_0 * n_1 * n_2

result = ((c_0 * m_s_0 * modinv(m_s_0, n_0)) +  (c_1 * m_s_1 * modinv(m_s_1, n_1)) + (c_2 * m_s_2 * modinv(m_s_2, n_2))) % N_012

a = precise_cube_root(result)

print(int_to_bytes(int(a),order="big"))

