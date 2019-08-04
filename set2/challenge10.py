#! /usr/bin/python

from Crypto.Cipher import AES

# https://www.cryptopals.com/sets/2/challenges/10
# Implement CBC mode

# wget https://www.cryptopals.com/static/challenge-data/10.txt --no-check-certificate

def xor(a,b):
    raw_a = a
    raw_b = b
    return "".join([chr(ord(raw_a[i])^ord(raw_b[i])) for i in range(len(raw_a))])

def cbc_decrypt(aes_ecb,ciphertext,IV,BLOCK_LEN=16):
    blocks = [ciphertext[i:i+BLOCK_LEN] for i in range(0,len(ciphertext),BLOCK_LEN)]
    
    prev = IV
    plaintext = ""
    for block in blocks:
        dec = aes_ecb.decrypt(block)
        plaintext += xor(dec,prev)
        prev = block
    return plaintext

def main():

    BLOCK_LEN = 16
    IV = "\x00"*BLOCK_LEN
    KEY = "YELLOW SUBMARINE"


    aes_ecb = AES.new(KEY, AES.MODE_ECB)

    with open("10.txt") as f:
        INPUT = "".join(f.readlines()).replace("\n","")

    ciphertext = INPUT.decode("base64")

    plaintext = cbc_decrypt(aes_ecb,ciphertext,IV)   
    print plaintext

main()
