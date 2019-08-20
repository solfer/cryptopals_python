#! /usr/bin/python

from random import randint
from Crypto.Cipher import AES

# https://www.cryptopals.com/sets/2/challenges/13
# ECB cut-and-paste

#We need to force "user" to be isolated 

def parser(x):
    a = x.split("&")
    d = {}
    for i in a:
        temp = i.split("=")
        d[temp[0]] = temp[1]
    return d

def profile_for(email):
    email = email.replace("=","").replace("&","")
    return "email="+email+"&uid=10&role=user"
    
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


    data = pkcs7_add(data,block_len)
    test = (aes_ecb.encrypt(data),"ECB")


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


def encrypt(aes_ecb,token,block_len = 16):
    token = pkcs7_add(token,block_len)
    return aes_ecb.encrypt(token)

def decrypt(aes_ecb,data):
    return aes_ecb.decrypt(data)

def main():

    block_len = 16
    key = random_aes_key(block_len)
    aes_ecb = AES.new(key, AES.MODE_ECB)

    email = "bob@email.com"
    #bob@email.com is the exact size to force "user" to be own its own block
    
    fake_email = "X"*(16-len("email="))+pkcs7_add("admin",block_len) + "@whatever.com"
    fake_blocks = encrypt(aes_ecb,profile_for(fake_email)) #the second block contains "admin" encrypted with padding

    user_blocks = encrypt(aes_ecb,profile_for(email))
    admin_blocks = user_blocks[:-16] + fake_blocks[16:32]
    
    print pkcs7_remove(decrypt(aes_ecb,admin_blocks))

main()
