#! /usr/bin/python3

# https://www.cryptopals.com/sets/2/challenges/9
# Implement PKCS#7 padding

import sys 
sys.path.append('..')

from cryptopals import pkcs7_add

def main():

    INPUT = "YELLOW SUBMARINE"
    RESULT = "YELLOW SUBMARINE\x04\x04\x04\x04"

    x = bytearray(INPUT,"ascii")
    r = bytearray(RESULT,"ascii")
    result = pkcs7_add(x,20)

    print("Success") if r == result else print("Fail")

main()
