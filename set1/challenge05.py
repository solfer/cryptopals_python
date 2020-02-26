#! /usr/bin/python3

# https://www.cryptopals.com/sets/1/challenges/5
# XOR INPUT with "ICE"

'''def alt_xor(a,b):
    raw_a = bytearray.fromhex(a)
    raw_b = bytearray.fromhex(b)
    
    xored = bytearray([raw_a[i]^raw_b[i] for i in range(len(raw_a))])
    print type(xored) 
    return bytearray.tohex(xored)
'''

def xor_cyclic(a,b):
    raw_a = bytearray(a,"ascii")
    raw_b = bytearray(b,"ascii")
    xored = bytearray([raw_a[i]^raw_b[i%len(raw_b)] for i in range(len(raw_a))])
    return xored


'''
INPUT1 = "Burning 'em, if you ain't quick and nimble"
INPUT2 = "I go crazy when I hear a cymbal"

RESULT1 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
RESULT2 = "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
'''

INPUT = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

RESULT = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"


result = xor_cyclic(INPUT,"ICE").hex()

print(RESULT)
print(result)

print("Success") if RESULT == result else print("Fail")
   
