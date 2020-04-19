#! /usr/bin/python3

from Crypto.Cipher import AES

from random import randint

# https://www.cryptopals.com/sets/4/challenges/27
# Recover the key from CBC with IV=Key

import sys 
sys.path.append('..')

from cryptopals import ctr,xor,random_aes_key,cbc_decrypt,cbc_encrypt

def random_aes_key(blocksize=16):
    return random_str(blocksize,blocksize)

def detect_high_ascii(text):
    for c in text:
        if c >= 0x80:
            return True
    return False
    
def f1(plaintext):
    global key
    aes_ecb = AES.new(key, AES.MODE_ECB)
    return cbc_encrypt(aes_ecb,plaintext,IV)
    
def f2(ciphertext):
    global key
    aes_ecb = AES.new(key, AES.MODE_ECB)
    plaintext = cbc_decrypt(aes_ecb,ciphertext,IV)
    if detect_high_ascii(plaintext):
        return plaintext
    else:
        return False

def blockfy(data, blocklen=16):
    return [data[i:i+blocklen] for i in range(0,len(data),blocklen)]

def main():
    blocksize = 16
    global key
    global IV
    #key = random_aes_key(blocksize)
    key = "YELLOW SUBMARINE"    
    IV = bytearray(key,"ascii")

    INPUT = bytearray("A"*32,"ascii")
    ciphertext = f1(INPUT)

    temp = blockfy(ciphertext)
    x = temp[0]
    x.extend(bytearray(16))
    x.extend(temp[0])
    #x = temp[0] + "\x00"*16 + temp[0]
    r = f2(x)
    if r:
        error = r
    else:
        print ("Bad luck!")
        exit()
    p = blockfy(error)
    k = xor(p[0],p[2])
    print (k)
main()
