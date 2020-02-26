#! /usr/bin/python3

# https://www.cryptopals.com/sets/1/challenges/2
# XOR both inputs

def xor(a,b):
    raw_a = bytearray.fromhex(a)
    raw_b = bytearray.fromhex(b)
    
    xored = bytearray([raw_a[i]^raw_b[i] for i in range(len(raw_a))])
    return xored


def alt_xor1(a,b):
    return hex(int(a,16)^int(b,16))[2:].replace("L","")

def alt_xor(a,b):
    raw_a = a.decode("hex")
    raw_b = b.decode("hex")

    return "".join([chr(ord(raw_a[i])^ord(raw_b[i])) for i in range(len(raw_a))]).encode("hex")


INPUT1 = "1c0111001f010100061a024b53535009181c"
INPUT2 = "686974207468652062756c6c277320657965"
RESULT = "746865206b696420646f6e277420706c6179"

result = xor(INPUT1,INPUT2).hex()

print(RESULT)
print(result)

print("Success") if RESULT == result else print("Fail")
   
