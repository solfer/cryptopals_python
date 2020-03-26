#! /usr/bin/python3

from Crypto.Cipher import AES

from random import randint

import base64

# https://www.cryptopals.com/sets/2/challenges/12
# Byte-at-a-time ECB decryption (Simple)

def detect_ecb(cipher):
    blocks = [cipher[i*16:(i+1)*16] for i in range(0,len(cipher)/16)]
    x = len(blocks)
    y = len(set(blocks))

    return not x==y


def random_aes_key(x):
    return random_str(x,x)

def random_str(start,stop):
    size = randint(start,stop)
    output = bytes()
    for i in range(size):
        output+=bytes(chr(randint(1,127)),"ascii") #this is me being lazy while converting code to Python3
    return output
    
def encryption_oracle(plaintext):
    block_len = 16
    key = KEY
    print(key)
    aes_ecb = AES.new(key, AES.MODE_ECB)

    unknown = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    data = bytearray(plaintext,"ascii")
    data.extend(bytearray(unknown,"ascii"))

    data = pkcs7_add(data,block_len)
    test = aes_ecb.encrypt(data)

    return test    



def pkcs7_add(data, block_len):
    pad = block_len - len(data)%block_len
    if pad < 0:
        return None
    elif pad == 0:
        return data + chr(block_len)*block_len
    return data + chr(pad)*pad

def pkcs7_remove(data):
    pad = ord(data[-1])
    return data[:-pad]

def main():

    #Detecting block size
    a = len(encryption_oracle("A"))
    for i in range(2,40):
        b = len(encryption_oracle("A"*i))
        if a != b:
            blocksize = b-a
            print ("Block size: %d bytes" %(blocksize,))
            break
        
    #Detecting ECB:
    for i in range(blocksize,3*blocksize):
        if detect_ecb(encryption_oracle("A"*i)):
            print ("ECB detected")
            break

    #Retrieving unknown text
    table = [encryption_oracle("B"*(blocksize-i)) for i in range(1,blocksize+1)]

    secret = ""
    for j in range(0,len(table[-1])):
        for i in range(1,blocksize+1):
            cipher = table[i-1][j*blocksize:(j+1)*blocksize]
            for c in range(256):
                temp = encryption_oracle("B"*(blocksize-i)+secret+chr(c))[j*blocksize:(j+1)*blocksize]
                if temp == cipher:
                    secret += chr(c)
                    break
    print (secret)

KEY = random_aes_key(16)
main()
