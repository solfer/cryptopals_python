#! /usr/bin/python

import sys 
sys.path.append('..')
from cryptopals import xor_hex_constant, is_printable, getChi2

# https://www.cryptopals.com/sets/1/challenges/4
# detect strings encrypted with a single-character XOR

# wget https://www.cryptopals.com/static/challenge-data/4.txt --no-check-certificate


def brute(s):
    candidates = []
    for k in range(1,255):
        x = xor_hex_constant(s,k)
        if is_printable(x):
            candidates.append((x,k,getChi2(x)))

    return candidates

def main():

    with open("4.txt") as f:
        INPUT = f.readlines()

    b = []
    for s in INPUT:
        b += brute(s.replace("\n",""))

    b.sort(key = lambda x: x[2])

    result = b[0][0]
    key = b[0][1]
    print (result)
    print (chr(key))

main()
