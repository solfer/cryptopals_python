#! /usr/bin/python3

from Crypto.Cipher import AES

from random import randint

# https://www.cryptopals.com/sets/2/challenges/16
# CBC bitflipping attacks

import sys 
sys.path.append('..')

from cryptopals import pkcs7_validation,random_aes_key,xor,cbc_encrypt,cbc_decrypt
    
def f1(plaintext):
    block_len = 16
    global key
    global IV
    aes_ecb = AES.new(key, AES.MODE_ECB)

    sanitised = plaintext.replace(";","';'").replace("=","'='")

    # A new block starts right after userdata=
    data = "comment1=cooking%20MCs;userdata="+sanitised+";comment2=%20like%20a%20pound%20of%20bacon"
    return cbc_encrypt(aes_ecb,bytearray(data,"ascii"),IV)
    
def f2(ciphertext):
    block_len = 16
    global key

    aes_ecb = AES.new(key, AES.MODE_ECB)
    plaintext = cbc_decrypt(aes_ecb,ciphertext,IV,validation=True)
    if ";admin=true;" in str(plaintext):
        return True
    else:
        return False
    
def main():
    blocksize = 16
    global key
    global IV
    key = random_aes_key(blocksize)
    IV = random_aes_key(blocksize)

    #Detecting block size
    a = len(f1("A"))
    for i in range(2,40):
        b = len(f1("A"*i))
        if a != b:
            blocksize = b-a
            print ("Block size: %d bytes" %(blocksize,))
            break


    text = chr(ord(";")^0x1)+"admin"+chr(ord("=")^0x1)+"true"+chr(ord(";")^0x1)+"AAAA" #this will be inserted on the third block
    # the idea is to modify the first (0) and the third (11) Xs to ; and the second (6) X to =
    # We need to change the bytes on the second block to propagate the changes on the third
    ciphertext = f1(text)

    pre = ciphertext[0:16]
    a = bytearray([ciphertext[16]^0x1])
    mid1 = ciphertext[17:22]
    b = bytearray([ciphertext[22]^0x1])
    mid2 = ciphertext[23:27]
    c = bytearray([ciphertext[27]^0x1])
    post = ciphertext[28:]
    x = pre
    x.extend(a)
    x.extend(mid1)
    x.extend(b)
    x.extend(mid2)
    x.extend(c)
    x.extend(post)
    #x = pre + a + mid1 + b + mid2 + c + post #I miss C

    if f2(x):
        print ("Success!!!")
    exit()

main()
