#! /usr/bin/python3

# https://www.cryptopals.com/sets/5/challenges/35
#Implement DH with negotiated groups, and break with malicious "g" parameters

from random import randint
from Crypto.Cipher import AES

import sys 
sys.path.append('..')

from cryptopals import random_aes_key,cbc_encrypt,cbc_decrypt,sha1,int_to_bytes

def main():

    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

################################################################################
###### MITM attack - Scenario 01: g = 1
################################################################################

    #User A generates A
    a = randint(0,p)
    A = pow(g, a, p)

    #User A sends (p,g,A) to M
    m_data = (p,g,A)

    #Use M send (p,g,A) to M
    g_m = 1
    b_data = (p,g_m,A)
    #User B generates B
    b = randint(0,b_data[0])
    B = pow(b_data[1], b, b_data[0])   #the result will be 1

    #User B sends B to M
    m_data2 = B
    a_data = m_data2 #let's send this 1 forward

    #User A calculates s, iv, key and encrypt a message
    #print a_data
    s_a = pow(a_data, a, p)   #s_a = 1
    #print s_a
    iv_a = random_aes_key(16)
    msg_a = bytearray("Super Secret Stuff123","ascii")
    #print hex(s_a)
    key_a = sha1(int_to_bytes(s_a))[:16]
    aes_ecb_a = AES.new(key_a, AES.MODE_ECB)
    enc_a = cbc_encrypt(aes_ecb_a, msg_a, iv_a)    
    #test = cbc_decrypt(aes_ecb_a, enc_a, iv_a)    
    #print test
    
    #User A sends encrypted message and iv to M
    m_data3 = enc_a+iv_a

    #M can recalculate the key and decrypt the message:
    key_m = sha1(b"\x01")[:16]
    #print key_m
    aes_ecb_m = AES.new(key_m, AES.MODE_ECB)
    msg_m = cbc_decrypt(aes_ecb_m, m_data3[:-16], m_data3[-16:],validation=True) #M knows the message (DONE)
    print ("Retrieved by M (scenario 1):",msg_m)

################################################################################
###### MITM attack - Scenario 02: g = p
################################################################################

    #User A generates A
    a = randint(0,p)
    A = pow(g, a, p)

    #User A sends (p,g,A) to M
    m_data = (p,g,A)

    #Use M send (p,g,A) to M
    g_m = p
    b_data = (p,g_m,A)
    
    #User B generates B
    b = randint(0,b_data[0])
    B = pow(b_data[1], b, b_data[0])   #the result will be 0

    #User B sends B to M
    m_data2 = B
    a_data = m_data2 #let's send this 0 forward

    #User A calculates s, iv, key and encrypt a message
    #print a_data
    s_a = pow(a_data, a, p)   #s_a = 0
    #print s_a
    
    iv_a = random_aes_key(16)
    msg_a = bytearray("Super Secret Stuff123","ascii")
    #print hex(s_a)
    key_a = sha1(int_to_bytes(s_a))[:16]
    aes_ecb_a = AES.new(key_a, AES.MODE_ECB)
    enc_a = cbc_encrypt(aes_ecb_a, msg_a, iv_a)    
    #test = cbc_decrypt(aes_ecb_a, enc_a, iv_a)    
    #print test
    
    #User A sends encrypted message and iv to M
    m_data3 = enc_a+iv_a

    #M can recalculate the key and decrypt the message:
    key_m = sha1(b'\x00')[:16]
    #print key_m
    aes_ecb_m = AES.new(key_m, AES.MODE_ECB)
    msg_m = cbc_decrypt(aes_ecb_m, m_data3[:-16], m_data3[-16:],validation=True) #M knows the message (DONE)
    print ("Retrieved by M (scenario 2):",msg_m)


################################################################################
###### MITM attack - Scenario 03: g = p-1
################################################################################

    #User A generates A
    a = randint(0,p)
    A = pow(g, a, p)

    #User A sends (p,g,A) to M
    m_data = (p,g,A)

    #Use M send (p,g,A) to M
    g_m = p-1
    b_data = (p,g_m,A)
    
    #User B generates B
    b = randint(0,b_data[0])
    B = pow(b_data[1], b, b_data[0])   #(p-1)^x % p == (-1)^x % p
                                       # if x is even: 1, if x is odd, p-1

    #User B sends B to M
    m_data2 = B
    a_data = m_data2 #sending the information forward

    #User A calculates s, iv, key and encrypt a message
    #print a_data
    s_a = pow(a_data, a, p)   #s_a is either p-1 or 1
    #print s_a

    iv_a = random_aes_key(16)
    msg_a = bytearray("Super Secret Stuff123","ascii")
    #print hex(s_a)
    key_a = sha1(int_to_bytes(s_a))[:16]
    aes_ecb_a = AES.new(key_a, AES.MODE_ECB)
    enc_a = cbc_encrypt(aes_ecb_a, msg_a, iv_a)    
    
    #User A sends encrypted message and iv to M
    m_data3 = enc_a+iv_a

    #M can calculate both possible keys and decrypt the message:
    key_m1 = sha1(b'\x01')[:16]
    key_m2 = sha1(int_to_bytes(g_m))[:16]

    for key_m in (key_m1,key_m2):
        aes_ecb_m = AES.new(key_m, AES.MODE_ECB)
        try:
            msg_m = cbc_decrypt(aes_ecb_m, m_data3[:-16], m_data3[-16:],validation=True) #M knows the message (DONE)
        except: #this is me being lazy. Note that it might break if the wrong key decrypts some garbage with the right padding
            pass
    print ("Retrieved by M (scenario 3):",msg_m)


main()
