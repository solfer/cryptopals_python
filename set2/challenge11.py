#! /usr/bin/python

from Crypto.Cipher import AES

from random import randint

# https://www.cryptopals.com/sets/2/challenges/11
# An ECB/CBC detection oracle

def detect_ecb(cipher):
    blocks = [cipher[i*16:(i+1)*16] for i in range(0,len(cipher)/16)]
    x = len(blocks)
    y = len(set(blocks))

    return not x==y


def random_aes_key(x):
    return random_str(x,x)

def random_str(start,stop):
    size = randint(start,stop)
    output = ""
    for i in range(size):
        output+=chr(randint(1,255))
    return output
    
def encryption_oracle(plaintext):
    block_len = 16
    key = random_aes_key(block_len)
    aes_ecb = AES.new(key, AES.MODE_ECB)

    data = random_str(5,10)+plaintext+random_str(5,10)


    if randint(0,1) == 0: #ECB
        data = pkcs7_add(data,block_len)
        test = (aes_ecb.encrypt(data),"ECB")
    else:                 #CBC
        iv = random_aes_key(block_len)
        test = (cbc_encrypt(aes_ecb,data,iv),"CBC")


    #Detection
    if detect_ecb(test[0]):
        print "ECB detected!"
    else:
        print "Guessed \"%s\" as CBC" % (test[1],)
    



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

def xor(a,b):
    raw_a = a
    raw_b = b
    return "".join([chr(ord(raw_a[i])^ord(raw_b[i])) for i in range(len(raw_a))])

def cbc_decrypt(aes_ecb,ciphertext,IV,BLOCK_LEN=16):
    blocks = [ciphertext[i:i+BLOCK_LEN] for i in range(0,len(ciphertext),BLOCK_LEN)]
    
    prev = IV
    plaintext = ""
    for block in blocks:
        dec = xor(aes_ecb.decrypt(block),prev)
        if block == blocks[-1]:
            plaintext += pkcs7_remove(dec)
        else:
            plaintext += dec
            prev = block
    return plaintext

def cbc_encrypt(aes_ecb,plaintext,IV,BLOCK_LEN=16):
    blocks = [plaintext[i:i+BLOCK_LEN] for i in range(0,len(plaintext),BLOCK_LEN)]
    
    prev = IV
    ciphertext = ""
    for block in blocks:
        if len(block) != BLOCK_LEN:
            block = pkcs7_add(block,BLOCK_LEN)
        enc = aes_ecb.encrypt(xor(block,prev))
        ciphertext += enc
        prev = enc
    return ciphertext

def test_cbc(aes_ecb,plaintext):
    BLOCK_LEN = 16
    IV = "\x00"*BLOCK_LEN
    KEY = "YELLOW SUBMARINE"
    print cbc_decrypt(aes_ecb,cbc_encrypt(aes_ecb,plaintext,IV),IV)

def main():
    with open("11.html") as f:
        plaintext = f.read()
    #plaintext = "Ehrsam, Meyer, Smith and Tuchman invented the Cipher Block Chaining (CBC) mode of operation in 1976.[11] In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. This way, each ciphertext block depends on all plaintext blocks processed up to that point. To make each message unique, an initialization vector must be used in the first block."*4

    for i in range(32):
        encryption_oracle(plaintext)


main()
