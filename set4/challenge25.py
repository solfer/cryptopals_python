#! /usr/bin/python

from Crypto.Cipher import AES
import struct
from random import randint

# https://www.cryptopals.com/sets/4/challenges/25
# Break "random access read/write" AES CTR

# wget https://www.cryptopals.com/static/challenge-data/25.txt --no-check-certificate

def xor(a,b):
    raw_a = a
    raw_b = b
    return "".join([chr(ord(raw_a[i])^ord(raw_b[i])) for i in range(len(raw_a))])


def random_aes_key(blocksize=16):
    return random_str(blocksize,blocksize)

def random_str(start,stop):
    size = randint(start,stop)
    output = ""
    for i in range(size):
        output+=chr(randint(1,255))
    return output

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

def recover_input():
    obj = AES.new('YELLOW SUBMARINE', AES.MODE_ECB)

    with open("25.txt") as f:
        INPUT = "".join(f.readlines())

    ciphertext = INPUT.decode("base64")
    plaintext = obj.decrypt(ciphertext)
    return plaintext

#I know it is totally inefficient, but I don't want to optimise it (aka do simple Maths) now
def edit(data,key,nonce,offset,newtext,blocksize=16):
    aes = AES.new(key, AES.MODE_ECB)
    nonce = struct.pack("<Q",nonce) #unsigned LE long long int (8 bytes)
    count = 0
    ciphertext = bytearray(data)

    for i in range((len(ciphertext))):
        if i % blocksize == 0:
            keystream = aes.encrypt(nonce+struct.pack("<q",count)) #signed LE long long int (8 bytes)
            count += 1
        if i >= offset and i < offset+len(newtext):
            ciphertext[i] = ord(newtext[i-offset]) ^ ord(keystream[i % blocksize])

    return str(ciphertext)

def edit_api(data,offset,newtext):
    return edit(data,key,nonce,offset,newtext)

def main():
    global key #put it here for the edit_api() function
    global nonce #put it here for the edit_api() function
    INPUT = recover_input()
    key = random_aes_key()
    nonce = 0
    ciphertext = ctr(INPUT,key,nonce)
    #print ctr(ciphertext,key,nonce)[:255]

    mask = edit_api(ciphertext,0,"A"*len(ciphertext))
    keystream = xor("A"*len(ciphertext),mask)
    plaintext = xor(ciphertext,keystream)
    print plaintext
main()
