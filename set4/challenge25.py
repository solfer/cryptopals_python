#! /usr/bin/python3

from Crypto.Cipher import AES
import struct, base64

# https://www.cryptopals.com/sets/4/challenges/25
# Break "random access read/write" AES CTR

# wget https://www.cryptopals.com/static/challenge-data/25.txt --no-check-certificate

import sys 
sys.path.append('..')

from cryptopals import ctr,xor,random_aes_key


def recover_input():
    aes = AES.new('YELLOW SUBMARINE', AES.MODE_ECB)

    with open("25.txt") as f:
        INPUT = "".join(f.readlines())

    ciphertext = base64.b64decode(INPUT)
    plaintext = aes.decrypt(ciphertext)
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

    return ciphertext

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
