#! /usr/bin/python3

import sys 
sys.path.append('..')
from cryptopals import xor_hex_constant, is_printable, getChi2

# https://www.cryptopals.com/sets/1/challenges/3
# XOR input with a constants and find which constant was used to encrypt input


def brute(s):
    candidates = []
    for k in range(1,255):
        x = xor_hex_constant(s,k)
        if is_printable(x):
            candidates.append((x,k,getChi2(x)))

    return candidates

INPUT = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
b = brute(INPUT)

b.sort(key = lambda x: x[2])

#print b[0]
result = b[0][0]
key = b[0][1]
print (result)
print (chr(key))

