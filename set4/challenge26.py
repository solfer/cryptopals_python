#! /usr/bin/python3

from Crypto.Cipher import AES
import struct
from random import randint

# https://www.cryptopals.com/sets/4/challenges/26
# CTR bitflipping

import sys 
sys.path.append('..')

from cryptopals import ctr,xor,random_aes_key

    
def f1(plaintext):
    global key
    global nonce
    
    sanitised = plaintext.replace(";","';'").replace("=","'='")

    data = "comment1=cooking%20MCs;userdata="+sanitised+";comment2=%20like%20a%20pound%20of%20bacon"
    return ctr(bytearray(data,"ascii"),key,nonce)
    
def f2(ciphertext):
    global key
    global nonce
    plaintext = ctr(ciphertext,key,nonce)
    if ";admin=true;" in str(plaintext):
        return True
    else:
        return False

def main():
    global key
    global nonce
    key = random_aes_key()
    nonce = 0
    text = chr(ord(";")^0x1)+"admin"+chr(ord("=")^0x1)+"true"+chr(ord(";")^0x1)+"AAAA" #this will be inserted on the third block
    ciphertext = f1(text)

    fake = ciphertext
    fake[32] ^=0x1
    fake[38] ^=0x1
    fake[43] ^=0x1

    if f2(fake):
        print ("Success!!!")
    exit()

main()
