#! /usr/bin/python3

from Crypto.Cipher import AES
import base64

import sys 
sys.path.append('..')

from cryptopals import xor,cbc_decrypt

# https://www.cryptopals.com/sets/2/challenges/10
# Implement CBC mode

# wget https://www.cryptopals.com/static/challenge-data/10.txt --no-check-certificate



def main():

    BLOCK_LEN = 16
    IV = "\x00"*BLOCK_LEN
    KEY = "YELLOW SUBMARINE"


    aes_ecb = AES.new(KEY, AES.MODE_ECB)

    with open("10.txt") as f:
        INPUT = "".join(f.readlines()).replace("\n","")

    ciphertext = base64.b64decode(INPUT)

    plaintext = cbc_decrypt(aes_ecb,ciphertext,IV)   
    print(plaintext)

main()
