#! /usr/bin/python3

from random import randint
from Crypto.Cipher import AES

# https://www.cryptopals.com/sets/2/challenges/13
# ECB cut-and-paste

import sys 
sys.path.append('..')

from cryptopals import random_aes_key,pkcs7_remove,pkcs7_add

#We need to force "user" to be isolated 

def parser(x):
    a = x.split("&")
    d = {}
    for i in a:
        temp = i.split("=")
        d[temp[0]] = temp[1]
    return d

def profile_for(email):
    email = bytearray(email.decode('ascii').replace("=","").replace("&",""),"ascii")
    token = bytearray("email=","ascii")
    token.extend(email)
    token.extend(bytearray("&uid=10&role=user","ascii"))
    return token

def encrypt(aes_ecb,token,block_len = 16):
    token = bytes(pkcs7_add(bytearray(token),block_len))
    return aes_ecb.encrypt(token)

def decrypt(aes_ecb,data):
    return aes_ecb.decrypt(data)

def main():

    block_len = 16
    key = random_aes_key(block_len)
    aes_ecb = AES.new(key, AES.MODE_ECB)

    email = "bob@email.com"
    #bob@email.com is the exact size to force "user" to be on its own block
    user_token = encrypt(aes_ecb,profile_for(bytearray(email,"ascii")))

   
    fake_email = bytearray("X"*(16-len("email=")),"ascii")
    fake_email.extend(pkcs7_add(bytearray("admin","ascii"),block_len))
    fake_email.extend(bytearray("@whatever.com","ascii"))

    fake_token = encrypt(aes_ecb,profile_for(fake_email)) #the second block contains "admin" encrypted with padding


    admin_token = user_token[:-16] + fake_token[16:32]

    print ("Original token (decrypted): ",pkcs7_remove(decrypt(aes_ecb,user_token)))
    print ("Fake token (decrypted):     ",pkcs7_remove(decrypt(aes_ecb,admin_token)))

main()
