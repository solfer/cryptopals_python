#! /usr/bin/python3

# https://www.cryptopals.com/sets/6/challenges/41
# Implement unpadded message recovery oracle

import sys 
sys.path.append('..')

from cryptopals import int_to_bytes,modinv,rsa_encrypt,rsa_decrypt,rsa_key_gen,test_primes,generate_rsa_prime

from random import randint

table = []

def decryption(cipher,priv_key):
    if cipher in table:
        return False
    else:
        table.append(cipher)
        return rsa_decrypt(cipher,priv_key[0],priv_key[1])

e = 3 # keeping e=3 
message = b"This is a super S3cr3t message!!!!"
m = int.from_bytes(message, byteorder='big')

#Generating RSA public and private keys
p = generate_rsa_prime()
q = generate_rsa_prime()

while (test_primes(p,q,e) != True):
    p = generate_rsa_prime()
    q = generate_rsa_prime()

pub_key, priv_key = rsa_key_gen(p,q,e)

#Encrypting message
e = pub_key[0]
n = pub_key[1]
c = rsa_encrypt(m,e,n)

print ("Original message:",int_to_bytes(decryption(c,priv_key),order="big"))
print (decryption(c,priv_key)) #Showing that it can't be done twice

# Attacker:
captured_cipher = c
captured_e = pub_key[0]
captured_n = pub_key[1]

S = randint(2,0xFFFFFFFF)

attacker_c = (pow(S,captured_e,captured_n) * captured_cipher) % captured_n

attacker_p = decryption(attacker_c,priv_key)

s_inv = modinv(S,captured_n)
recovered_p = attacker_p * s_inv % captured_n
print ("Recovered message",int_to_bytes(recovered_p,order="big"))


#print(int_to_bytes(int(a),order="big"))

