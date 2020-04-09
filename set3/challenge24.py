#! /usr/bin/python3

# https://www.cryptopals.com/sets/3/challenges/24
# Create the MT19937 stream cipher and break it

import time
import struct
from random import randint


import sys 
sys.path.append('..')

from cryptopals import xor,random_str

(w, n, m, r) = (32, 624, 397, 31)
a = 0x9908B0DF
(u,d) = (11,0xFFFFFFFF)
(s,b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
l = 18

MT = [0]*n #Creating MT

f = 1812433253
index = n+1
lower_mask = (1 << r) - 1 # 0x7FFFFFFF
upper_mask = ((1 << w) -1) & (0xFFFFFFFF ^ lower_mask) # lowest w bits of (not lower_mask) 0x80000000


# Initialize the generator from a seed
def seed_mt(seed):
    global MT
    global n
    global index
    index = n
    MT[0] = seed
    for i in range(1,n):
        MT[i] = ((1 << w) -1) & (f * (MT[i-1] ^ (MT[i-1] >> (w-2)))+i)# & d

# Extract a tempered value based on MT[index] calling twist() every n numbers
def extract_number():
    global index
    if index >= n:
        if index > n:
            #Error, generator was never seeded
            # Alternatively, seed with constant value; 5489 is used in reference C code
            seed_mt(5489)
        twist()
    
    y = MT[index]
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)

    index += 1
    return ((1 << w) -1) & y #return lowest w bits of y

# Generate the next n values from the series x_i
def twist():
    global n
    global index
    global MT
    for i in range(0,n):
        x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
        xA = (x >> 1) #xA = (x >> 1) & d
        if x % 2 != 0: #lowest bit of x is 1
            xA = xA ^ a

        MT[i] = MT[(i+m) % n] ^ xA
    index = 0

def mt19937_stream_cipher(data,key,blocksize=4):
    seed_mt(key)
    ciphertext = bytearray(data)
    int_to_bytes = struct.Struct('<I').pack

    for i in range((len(ciphertext))):
        if i % blocksize == 0:
            keystream = int_to_bytes(extract_number())
        ciphertext[i] ^= keystream[i % blocksize]

    return ciphertext

def recover_key(known,ciphertext):
    fake = bytearray(len(ciphertext)-len(known))
    fake.extend(known)
    temp = xor(fake,ciphertext)
    x = [temp[i:i+4] for i in range(0,len(temp),4)]
    a = struct.Struct('<I').unpack(x[-2])[0] #getting the penultimate block
    
    for K in range(0x10000):
        seed_mt(K)
        for i in range(0,len(ciphertext)-4,4):
            w = extract_number()
        if w == a:
            return K

def gen_token():
    s_time = int(time.time()) & 0xFFFF
    seed_mt(s_time)
    return extract_number()

def verify_token(token):
    interval = 15*60 # 15 min
    s_time = int(time.time()) - interval # Current time - interval
    for i in range (interval+1):
        K = (s_time + i) & 0xFFFF
        seed_mt(K)
        if extract_number() == token:
            return True
    return False

def main():
    known = bytearray("A"*14,"ascii")
    secret = random_str(4,50)
    data = bytearray(secret)
    data.extend(known)
    key = randint(0x0000,0xFFFF)

    print ("Key chosen:",hex(key))
    ciphertext = mt19937_stream_cipher(data,key)
    decrypted = mt19937_stream_cipher(ciphertext,key)

    if decrypted == data:
        print ("Decryption works")

    print ("Key retrieved:",hex(recover_key(known,ciphertext)))

    token = gen_token()
    if verify_token(token):
        print ("Token is valid")

main()
