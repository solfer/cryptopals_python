#! /usr/bin/python

from Crypto.Cipher import AES

from random import randint

# https://www.cryptopals.com/sets/2/challenges/16
# CBC bitflipping attacks


def random_aes_key(blocksize=16):
    return random_str(blocksize,blocksize)

def random_str(start,stop):
    size = randint(start,stop)
    output = ""
    for i in range(size):
        output+=chr(randint(1,255))
    return output

def detect_high_ascii(text):
    for c in text:
        if c >= 128:
            return True
    return False
    
def f1(plaintext):
    global key
    aes_ecb = AES.new(key, AES.MODE_ECB)
    return cbc_encrypt(aes_ecb,plaintext)
    
def f2(ciphertext):
    global key
    aes_ecb = AES.new(key, AES.MODE_ECB)
    plaintext = cbc_decrypt(aes_ecb,ciphertext)
    if detect_high_ascii(plaintext):
        return plaintext
    else:
        return False

def pkcs7_add(data, block_len=16):
    pad = block_len - len(data)%block_len
    if pad < 0:
        return None
    elif pad == 0:
        return data + chr(block_len)*block_len
    return data + chr(pad)*pad

def pkcs7_validation(data, block_len=16):
    return data # remove padding error because FML
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

def cbc_decrypt(aes_ecb,ciphertext,BLOCK_LEN=16):
    blocks = [ciphertext[i:i+BLOCK_LEN] for i in range(0,len(ciphertext),BLOCK_LEN)]
    
    prev = IV
    plaintext = ""
    for block in blocks:
        dec = xor(aes_ecb.decrypt(block),prev)
        if block == blocks[-1]:
            plaintext += pkcs7_validation(dec)
        else:
            plaintext += dec
            prev = block
    return plaintext

def blockfy(data, blocklen=16):
    return [data[i:i+blocklen] for i in range(0,len(data),blocklen)]

def cbc_encrypt(aes_ecb,plaintext,BLOCK_LEN=16):
    padded_plaintext = pkcs7_add(plaintext,BLOCK_LEN)
    blocks = [padded_plaintext[i:i+BLOCK_LEN] for i in range(0,len(padded_plaintext),BLOCK_LEN)]
    
    prev = IV
    ciphertext = ""
    for block in blocks:
        enc = aes_ecb.encrypt(xor(block,prev))
        ciphertext += enc
        prev = enc
    return ciphertext


def main():
    blocksize = 16
    global key
    global IV
    #key = random_aes_key(blocksize)
    key = "YELLOW SUBMARINE"    
    IV = key

    INPUT = "A"*32
    ciphertext = f1(INPUT)
    data = bytearray(ciphertext)
    temp = blockfy(ciphertext)
    x = temp[0] + "\x00"*16 + temp[0]
    r = f2(x)
    if r:
        error = r
    else:
        print "Bad luck!"
        exit()
    p = blockfy(error)
    k = xor(p[0],p[2])
    print k
main()
