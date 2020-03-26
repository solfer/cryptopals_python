#! /usr/bin/python3

import sys 
sys.path.append('..')
from cryptopals import xor_str_cyclic

# https://www.cryptopals.com/sets/1/challenges/5
# XOR INPUT with "ICE"



'''
INPUT1 = "Burning 'em, if you ain't quick and nimble"
INPUT2 = "I go crazy when I hear a cymbal"

RESULT1 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
RESULT2 = "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
'''

INPUT = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

RESULT = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"


result = xor_str_cyclic(INPUT,"ICE").hex()

print(RESULT)
print(result)

print("Success") if RESULT == result else print("Fail")
   
