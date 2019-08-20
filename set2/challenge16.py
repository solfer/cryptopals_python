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
    
def f1(plaintext):
    block_len = 16
    global key
    aes_ecb = AES.new(key, AES.MODE_ECB)

    sanitised = plaintext.replace(";","';'").replace("=","'='")

    # A new block starts right after userdata=
    data = "comment1=cooking%20MCs;userdata="+sanitised+";comment2=%20like%20a%20pound%20of%20bacon"
    return cbc_encrypt(aes_ecb,data)
    
def f2(ciphertext):
    block_len = 16
    global key
    aes_ecb = AES.new(key, AES.MODE_ECB)
    plaintext = cbc_decrypt(aes_ecb,ciphertext)
    if ";admin=true;" in plaintext:
        return True
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
    pad_size = ord(data[-1])
    padding = data[-pad_size:]
    if len(set(padding)) != 1:
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
    key = random_aes_key(blocksize)
    IV = random_aes_key(blocksize)

    #Detecting block size
    a = len(f1("A"))
    for i in range(2,40):
        b = len(f1("A"*i))
        if a != b:
            blocksize = b-a
            print "Block size: %d bytes" %(blocksize,)
            break


    text = chr(ord(";")^0x1)+"admin"+chr(ord("=")^0x1)+"true"+chr(ord(";")^0x1)+"AAAA" #this will be inserted on the third block
    # the idea is to modify the first (0) and the third (11) Xs to ; and the second (6) X to =
    # We need to change the bytes on the second block to propagate the changes on the third
    ciphertext = f1(text)
    
    pre = ciphertext[0:16]
    a = chr(ord(ciphertext[16])^0x1)
    mid1 = ciphertext[17:22]
    b = chr(ord(ciphertext[22])^0x1)
    mid2 = ciphertext[23:27]
    c = chr(ord(ciphertext[27])^0x1)
    post = ciphertext[28:]
    x = pre + a + mid1 + b + mid2 + c + post #I miss C
    if f2(x):
        print "Success!!!"
    exit()

main()
