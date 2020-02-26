#! /usr/bin/python3

from Crypto.Cipher import AES
import base64

# https://www.cryptopals.com/sets/1/challenges/7
# AES in ECB mode

# wget https://www.cryptopals.com/static/challenge-data/7.txt --no-check-certificate



def main():
    obj = AES.new('YELLOW SUBMARINE', AES.MODE_ECB)

    with open("7.txt") as f:
        INPUT = "".join(f.readlines()).replace("\n","")

    ciphertext = base64.b64decode(INPUT)
    plaintext = obj.decrypt(ciphertext)
    print (plaintext)

main()
