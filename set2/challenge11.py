#! /usr/bin/python3

from Crypto.Cipher import AES

from random import randint

# https://www.cryptopals.com/sets/2/challenges/11
# An ECB/CBC detection oracle

import sys 
sys.path.append('..')

from cryptopals import detect_ecb,random_aes_key,random_str,cbc_encrypt,pkcs7_add

  
def encryption_oracle(plaintext):
    block_len = 16
    key = random_aes_key(block_len)
    aes_ecb = AES.new(key, AES.MODE_ECB)
    data = bytearray(random_str(5,10))
    data.extend(bytearray(plaintext,"ascii"))
    data.extend(random_str(5,10))

    if randint(0,1) == 0: #ECB
        data = bytes(pkcs7_add(data,block_len)) #turning into bytes so aes_ecb won't bitch
        test = (aes_ecb.encrypt(data),"ECB")
    else:                 #CBC
        iv = random_aes_key(block_len)
        test = (cbc_encrypt(aes_ecb,data,iv),"CBC")


    #Detection
    if detect_ecb(test[0]):
        print("ECB detected!")
    else:
        print("Guessed \"%s\" as CBC" % (test[1],))

def main():
    with open("11.html") as f:
        plaintext = f.read()
    #plaintext = "Ehrsam, Meyer, Smith and Tuchman invented the Cipher Block Chaining (CBC) mode of operation in 1976.[11] In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. This way, each ciphertext block depends on all plaintext blocks processed up to that point. To make each message unique, an initialization vector must be used in the first block."*4

    for i in range(32):
        encryption_oracle(plaintext)


main()
