#! /usr/bin/python

from Crypto.Cipher import AES
import struct
from random import randint

# https://www.cryptopals.com/sets/4/challenges/26
# CTR bitflipping


def random_aes_key(blocksize=16):
    return random_str(blocksize,blocksize)

def random_str(start,stop):
    size = randint(start,stop)
    output = ""
    for i in range(size):
        output+=chr(randint(1,255))
    return output
    
def f1(plaintext):
    global key
    global nonce
    
    sanitised = plaintext.replace(";","';'").replace("=","'='")

    data = "comment1=cooking%20MCs;userdata="+sanitised+";comment2=%20like%20a%20pound%20of%20bacon"
    return ctr(data,key,nonce)
    
def f2(ciphertext):
    global key
    global nonce
    plaintext = ctr(ciphertext,key,nonce)
    if ";admin=true;" in plaintext:
        return True
    else:
        return False
    

def xor(a,b):
    raw_a = a
    raw_b = b
    return "".join([chr(ord(raw_a[i])^ord(raw_b[i])) for i in range(len(raw_a))])

def ctr(data,key,nonce,blocksize=16):
    aes = AES.new(key, AES.MODE_ECB)
    nonce = struct.pack("<Q",nonce) #unsigned LE long long int (8 bytes)
    count = 0
    ciphertext = bytearray(data)

    for i in range((len(ciphertext))):
        if i % blocksize == 0:
            keystream = aes.encrypt(nonce+struct.pack("<q",count)) #signed LE long long int (8 bytes)
            count += 1
        ciphertext[i] ^= ord(keystream[i % blocksize])

    return str(ciphertext)

def main():
    global key
    global nonce
    key = random_aes_key()
    nonce = 0
    text = chr(ord(";")^0x1)+"admin"+chr(ord("=")^0x1)+"true"+chr(ord(";")^0x1)+"AAAA" #this will be inserted on the third block
    ciphertext = f1(text)
    
    pre = ciphertext[0:32]
    a = chr(ord(ciphertext[32])^0x1)
    mid1 = ciphertext[33:38]
    b = chr(ord(ciphertext[38])^0x1)
    mid2 = ciphertext[39:43]
    c = chr(ord(ciphertext[43])^0x1)
    post = ciphertext[44:]
    x = pre + a + mid1 + b + mid2 + c + post #I miss C
    if f2(x):
        print "Success!!!"
    exit()

main()
