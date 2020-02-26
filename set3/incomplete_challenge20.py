#! /usr/bin/python

from Crypto.Cipher import AES
from random import randint,seed
import struct

# https://www.cryptopals.com/sets/2/challenges/20
# Break fixed-nonce CTR statistically

# wget https://cryptopals.com/static/challenge-data/20.txt --no-check-certificate


seed(a=3)

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

def main():
    key = random_aes_key()
    nonce = 0

    with open("20.txt") as f:
        INPUT = f.readlines()
    b = []
    for s in INPUT:
        b.append(s.decode("base64"))

    ciphers = []
    for data in b:
        ciphers.append(ctr(data,key,nonce))

    n = min([len(i) for i in ciphers])
    print n

    for i in range(n):
        

    for i in ciphers:
        print [i]
main()
