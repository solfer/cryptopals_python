#! /usr/bin/python3

from Crypto.Cipher import AES

from random import randint

import base64

# https://www.cryptopals.com/sets/2/challenges/14
# Byte-at-a-time ECB decryption (Harder)

import sys 
sys.path.append('..')

from cryptopals import detect_ecb,random_aes_key,random_str,pkcs7_add
    
def encryption_oracle(plaintext):
    global random_string
    block_len = 16
    key = KEY
    aes_ecb = AES.new(key, AES.MODE_ECB)

    unknown = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

    data = bytearray(random_string)
    data.extend(bytearray(plaintext.encode()))
    data.extend(bytearray(unknown))

    data = bytes(pkcs7_add(data,block_len))
    test = aes_ecb.encrypt(data)

    return test    

def main():
    
    global random_string #Lazy me

    random_string = random_str(1,32*4)
    #Detecting block size
    a = len(encryption_oracle("A"))
    for i in range(2,40):
        b = len(encryption_oracle("A"*i))
        if a != b:
            blocksize = b-a
            print ("Block size: %d bytes" %(blocksize,))
            break
        
    #Detecting ECB: #Not needed. Here for the lolz
    for i in range(blocksize,3*blocksize):
        if detect_ecb(encryption_oracle("A"*i)):
            print ("ECB detected")
            break

    #Detecting size of the random string
    for i in range(blocksize,3*blocksize):
        cipher = encryption_oracle("A"*i)
        if detect_ecb(cipher): #Lazy me again.
            blocks = [cipher[j*16:(j+1)*16] for j in range(0,int(len(cipher)/16))]
            for j in range(1,len(blocks)):
                if blocks[j] == blocks[j+1]:
                    size_random_string = (j)*blocksize - i%blocksize
                    break
            break

    print ("Size of random string:", size_random_string)
    offset = (-size_random_string % blocksize)
    padding = "X"*offset
    print ("Length of padding:", len(padding),"\n")

    #Retrieving unknown text:
    table = [encryption_oracle(padding+"B"*(blocksize-i)) for i in range(1,blocksize+1)]

    secret = ""
    skip = int((offset+size_random_string)/blocksize)

    for j in range(skip,len(table[-1])):
        for i in range(1,blocksize+1):
            cipher = table[i-1][j*blocksize:(j+1)*blocksize]
            for c in range(256):
                temp = encryption_oracle(padding+"B"*(blocksize-i)+secret+chr(c))[j*blocksize:(j+1)*blocksize]
                if temp == cipher:
                    secret += chr(c)
                    break
    print (secret)

KEY = random_aes_key(16)
main()
