#! /usr/bin/python3

import base64

import sys 
sys.path.append('..')
from cryptopals import getChi2_space,xor_str_constant

# https://www.cryptopals.com/sets/1/challenges/6
# Break repeating-key XOR

# wget https://www.cryptopals.com/static/challenge-data/6.txt --no-check-certificate


def brute(s):
    candidates = []
    for k in range(0,256):
        x = xor_str_constant(s,k)

        candidates.append((x,chr(k),getChi2_space(x)))
    return candidates



def hamming_distance(s1,s2):
    if len(s1) != len(s2):
        return None
    return sum([bin(s1[i]^s2[i]).count("1") for i in range(len(s1))])



def key_candidates(data):
    dists = []
    for KEYSIZE in range(2,41):
        h1 = 1.0*hamming_distance(data[0:KEYSIZE],data[KEYSIZE:2*KEYSIZE])/KEYSIZE
        h2 = 1.0*hamming_distance(data[2*KEYSIZE:3*KEYSIZE],data[3*KEYSIZE:4*KEYSIZE])/KEYSIZE
        h3 = 1.0*hamming_distance(data[4*KEYSIZE:5*KEYSIZE],data[5*KEYSIZE:6*KEYSIZE])/KEYSIZE
        dists.append((KEYSIZE,(h1+h2+h3)/3))
    dists.sort(key = lambda x: x[1])
    return dists

def main():

    with open("6.txt") as f:
        INPUT = base64.b64decode("".join(f.readlines()).replace("\n",""))

    dists = key_candidates(INPUT)

    keysizes = [i[0] for i in dists[:6]]   #Getting the 6 most likely candidates
    
    possible_keys = []
    for KEYSIZE in keysizes:
        blocks = [INPUT[i*KEYSIZE:(i+1)*KEYSIZE] for i in range(1+int(len(INPUT)/KEYSIZE))]
        t_blocks = [""]*KEYSIZE

        for block in blocks:
            for i in range(len(block)): #not using KEYSIZE because I'm lazy
                t_blocks[i] += chr(block[i])
        
        key = ""
        for s in t_blocks:
            b = brute(s)
            b.sort(key = lambda x: x[2])
            if b[0][2] == 10000000000:
                key = ""
                break
            key += b[0][1]
        if key:
            possible_keys.append(key)

    for key in possible_keys:
        decrypted = ""
        print ("Decrypting using \"%s\"\n" %(key,))
        for i,c in enumerate(INPUT):
             decrypted+=chr(c^ord(key[i%len(key)]))
        print (decrypted)

main()
