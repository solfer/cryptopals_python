#! /usr/bin/python3

from Crypto.Cipher import AES

from random import randint,seed
import base64

#seed(a=3)
# https://www.cryptopals.com/sets/3/challenges/17
# The CBC padding oracle

import sys 
sys.path.append('..')

from cryptopals import cbc_decrypt,cbc_encrypt,random_aes_key,pkcs7_validation

INPUT = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

   
def f1():
    block_len = 16
    global key

    data = INPUT[randint(0,len(INPUT)-1)] #padding is added by the encryption function

    key = random_aes_key(16)
    iv = random_aes_key(16)

    aes_ecb = AES.new(key, AES.MODE_ECB)

    return (cbc_encrypt(aes_ecb,bytearray(data,"ascii"),iv),iv)
    
def f2(ciphertext,iv):
    block_len = 16
    global key
    aes_ecb = AES.new(key, AES.MODE_ECB)
    try:
        plaintext = cbc_decrypt(aes_ecb,ciphertext,iv,validation=True)
        #plaintext = cbc_decrypt(aes_ecb,ciphertext,iv)
        #pkcs7_validation(plaintext)
        return True
    except ValueError:
        return False
    
def blockfy(data, blocklen=16):
    return [data[i:i+blocklen] for i in range(0,len(data),blocklen)]

def main():
    blocksize = 16
    global key
    ciphertext,iv = f1()

    decrypted = ""
    blocks = blockfy(iv+ciphertext)
    l = len(blocks)-1
    for b in range(l,0,-1):
        for j in range(1,blocksize+1):
            flag = False
            for i in range(1,256):
                prev_block = bytearray(blocks[b-1])
                cur_block = blocks[b]

                for k in range(1,j):
                    prev_block[blocksize-k] = prev_block[blocksize-k] ^ ord(decrypted[-k-(l-b)*blocksize]) ^ j #0x04
                prev_block[blocksize-j] = prev_block[blocksize-j] ^ i
                s = prev_block
                s.extend(cur_block)
                if f2(s,iv):
                    flag = True
                    decrypted = chr(i^j) + decrypted

            if not flag:
                i = 0
                decrypted = chr(i^j) + decrypted
    
    #print(decrypted)
    print (base64.b64decode(pkcs7_validation(bytearray(decrypted,"ascii"))))

main()
