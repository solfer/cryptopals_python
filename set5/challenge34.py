#! /usr/bin/python3

# https://www.cryptopals.com/sets/5/challenges/34
#Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

from random import randint
from Crypto.Cipher import AES

import sys 
sys.path.append('..')

from cryptopals import random_aes_key,cbc_encrypt,cbc_decrypt,sha1

def int_to_bytes(x):
    from math import log2
    if x == 0:
        return b'\x00'
    return x.to_bytes(int(log2(x)/8)+1, byteorder="little", signed=False)

def main():

    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    #User A generates A
    a = randint(0,p)
    A = pow(g, a, p)

    #User A sends (p,g,A) to B
    b_data = (p,g,A)

    #User B generates B
    b = randint(0,b_data[0])
    B = pow(b_data[1], b, b_data[0])

    #User B sends B to A
    a_data = B

    #User A calculates s, iv, key and encrypt a message

    s_a = pow(a_data, a, p)
    iv_a = random_aes_key(16)
    msg_a = bytearray("Super Secret Stuff123","ascii")
    key_a = sha1(int_to_bytes(s_a))[:16]
    aes_ecb_a = AES.new(key_a, AES.MODE_ECB)
    enc_a = cbc_encrypt(aes_ecb_a, msg_a, iv_a)
    #test = cbc_decrypt(aes_ecb_a, enc_a, iv_a)    
    #print test
    
    #User A sends encrypted message and iv to B
    b_data2 = enc_a+iv_a

    #User B calculates s, key, retrieves iv and decrypts the message:
    s_b = pow(b_data[2],b,p)
  
    #print s_a == s_b

    key_b = sha1(int_to_bytes(s_b))[:16]
    aes_ecb_b = AES.new(key_b, AES.MODE_ECB)
    msg_b = cbc_decrypt(aes_ecb_b,b_data2[:-16],b_data2[-16:],validation=True)

    #User B generates an IV, encrypts the message retrieved and send it with the IV to A
    iv_b = random_aes_key(16)
    enc_b = cbc_encrypt(aes_ecb_b, msg_b, iv_b)
    
    a_data2 = enc_b+iv_b

    #A gets the iv, decrypts the data and verify the message:
    msg_temp = cbc_decrypt(aes_ecb_a,a_data2[:-16],a_data2[-16:],validation=True)
    print (msg_a == msg_temp)


################################################################################
###### MITM attack 
################################################################################

    #User A generates A
    a = randint(0,p)
    A = pow(g, a, p)

    #User A sends (p,g,A) to M
    m_data = (p,g,A)

    #Use M send (p,g,p) to M
    b_data = (m_data[0],g,m_data[0])
    
    #User B generates B
    b = randint(0,b_data[0])
    B = pow(b_data[1], b, b_data[0])

    #User B sends B to M
    m_data2 = B

    #User M sends p to A
    a_data = p

    #User A calculates s, iv, key and encrypt a message

    s_a = pow(a_data, a, p) # (p ** a) % p == (0 ** a) % p == 0
    iv_a = random_aes_key(16)
    msg_a = bytearray("Super Secret Stuff123","ascii")
    print (hex(s_a))
    key_a = sha1(int_to_bytes(s_a))[:16]
    aes_ecb_a = AES.new(key_a, AES.MODE_ECB)
    enc_a = cbc_encrypt(aes_ecb_a, msg_a, iv_a)    
    #test = cbc_decrypt(aes_ecb_a, enc_a, iv_a)    
    #print test
    
    #User A sends encrypted message and iv to M
    m_data3 = enc_a+iv_a

    #User M relays message to B
    b_data2 = m_data3

    #User B calculates s, key, retrieves iv and decrypts the message:
    s_b = pow(b_data[2],b,p)
    #print s_a == s_b
    key_b = sha1(int_to_bytes(s_b))[:16]
    
    aes_ecb_b = AES.new(key_b, AES.MODE_ECB)
    msg_b = cbc_decrypt(aes_ecb_b,b_data2[:-16],b_data2[-16:],validation=True)

    #User B generates an IV, encrypts the message retrieved and send it with the IV to M
    iv_b = random_aes_key(16)
    enc_b = cbc_encrypt(aes_ecb_b, msg_b, iv_b)
    
    m_data4 = enc_b+iv_b
    
    #User M relays message to A
    a_data2 = m_data4

    #A gets the iv, decrypts the data and verify the message:
    msg_temp = cbc_decrypt(aes_ecb_a,a_data2[:-16],a_data2[-16:],validation=True)
    print (msg_a == msg_temp)

    #M can decrypt the message as well:
    key_m = sha1(b'\x00')[:16]
    aes_ecb_m = AES.new(key_m, AES.MODE_ECB)
    msg_m = cbc_decrypt(aes_ecb_m,m_data4[:-16],m_data4[-16:],validation=True)
    print (msg_a == msg_m)
main()
