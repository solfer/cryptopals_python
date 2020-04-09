#! /usr/bin/python3

import base64

# https://www.cryptopals.com/sets/2/challenges/18
# Implement CTR, the stream cipher mode

import sys 
sys.path.append('..')

from cryptopals import ctr

def main():
    key = "YELLOW SUBMARINE"
    INPUT = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    nonce = 0

    data = base64.b64decode(INPUT)

    print (ctr(data,key,nonce))

main()
