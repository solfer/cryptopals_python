#! /usr/bin/python

from Crypto.Cipher import AES

from random import randint,seed

#seed(a=3)
# https://www.cryptopals.com/sets/2/challenges/17
# The CBC padding oracle

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

def random_aes_key(blocksize=16):
    return random_str(blocksize,blocksize)

def random_str(start,stop):
    size = randint(start,stop)
    output = ""
    for i in range(size):
        output+=chr(randint(1,255))
    return output
    
def f1():
    block_len = 16
    global key

    data = INPUT[randint(0,len(INPUT)-1)] #padding is added by the encryption function

    key = random_aes_key()

    iv = random_aes_key()

    aes_ecb = AES.new(key, AES.MODE_ECB)

    return (cbc_encrypt(aes_ecb,data,iv),iv)
    
def f2(ciphertext,iv):
    block_len = 16
    global key
    aes_ecb = AES.new(key, AES.MODE_ECB)
    try:
        plaintext = cbc_decrypt(aes_ecb,ciphertext,iv)
        #pkcs7_validation(plaintext)
        return True
    except ValueError:
        return False
    


def pkcs7_add(data, block_len=16):
    pad = block_len - len(data)%block_len
    if pad < 0:
        return None
    elif pad == 0:
        return data + chr(block_len)*block_len
    return data + chr(pad)*pad

def pkcs7_validation(data, block_len=16):
    pad_size = ord(data[-1])
    padding = data[-pad_size:]
    if len(set(padding)) != 1 or len(data)%block_len != 0:
        raise ValueError("Invalid padding")
        raise Exception("Bad padding")
    return data[:-pad_size]


def xor(a,b):
    raw_a = a
    raw_b = b
    return "".join([chr(ord(raw_a[i])^ord(raw_b[i])) for i in range(len(raw_a))])

def cbc_decrypt(aes_ecb,ciphertext,iv,BLOCK_LEN=16):
    blocks = [ciphertext[i:i+BLOCK_LEN] for i in range(0,len(ciphertext),BLOCK_LEN)]
    
    prev = iv
    plaintext = ""
    for block in blocks:
        dec = xor(aes_ecb.decrypt(block),prev)
        if block == blocks[-1]:
            plaintext += pkcs7_validation(dec)
        else:
            plaintext += dec
            prev = block
    return plaintext

def cbc_encrypt(aes_ecb,plaintext,iv,BLOCK_LEN=16):
    padded_plaintext = pkcs7_add(plaintext,BLOCK_LEN)
    blocks = [padded_plaintext[i:i+BLOCK_LEN] for i in range(0,len(padded_plaintext),BLOCK_LEN)]
    
    prev = iv
    ciphertext = ""
    for block in blocks:
        enc = aes_ecb.encrypt(xor(block,prev))
        ciphertext += enc
        prev = enc
    return ciphertext

def modify_string(s,pos,value):
    x = s[:pos]+value+s[pos+1:]
    return x

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
                s = str(prev_block)+cur_block
                if f2(s,iv):
                    flag = True
                    decrypted = chr(i^j) + decrypted

            if not flag:
                i = 0
                decrypted = chr(i^j) + decrypted
            
    print pkcs7_validation(decrypted).decode('base64')
main()
