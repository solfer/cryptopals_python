#! /usr/bin/python

from Crypto.Cipher import AES

# https://www.cryptopals.com/sets/1/challenges/8
# Detect AES in ECB mode

# wget https://www.cryptopals.com/static/challenge-data/8.txt --no-check-certificate


def detect_ecb(cipher):
    blocks = [cipher[i*32:(i+1)*32] for i in range(0,len(cipher)/32)]
    x = len(blocks)
    y = len(set(blocks))

    return not x==y

def main():

    with open("8.txt") as f:
        INPUT = f.readlines()

    for cipher in INPUT:
        cipher = cipher.replace("\n","")
        if detect_ecb(cipher):
            print(cipher)
            return #Only one of them is encrypted with ECB

main()
