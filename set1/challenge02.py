#! /usr/bin/python3

# https://www.cryptopals.com/sets/1/challenges/2
# XOR both inputs

import sys 
sys.path.append('..')
from cryptopals import xor_hex

INPUT1 = "1c0111001f010100061a024b53535009181c"
INPUT2 = "686974207468652062756c6c277320657965"
RESULT = "746865206b696420646f6e277420706c6179"

result = xor_hex(INPUT1,INPUT2).hex()

print(RESULT)
print(result)

print("Success") if RESULT == result else print("Fail")
   
