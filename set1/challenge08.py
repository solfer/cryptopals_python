#! /usr/bin/python3

from Crypto.Cipher import AES

# https://www.cryptopals.com/sets/1/challenges/8
# Detect AES in ECB mode

# wget https://www.cryptopals.com/static/challenge-data/8.txt --no-check-certificate

import sys 
sys.path.append('..')

from cryptopals import detect_ecb

def main():

    with open("8.txt") as f:
        INPUT = f.readlines()

    for cipher in INPUT:
        cipher = bytearray.fromhex(cipher.replace("\n",""))
        if detect_ecb(cipher):
            print(cipher.hex())
            return #Only one of them is encrypted with ECB

main()
