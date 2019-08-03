#! /usr/bin/python

import string

# https://www.cryptopals.com/sets/1/challenges/4
# detect strings encrypted with a single-character XOR


## https://crypto.stackexchange.com/questions/30209/developing-algorithm-for-detecting-plain-text-via-frequency-analysis
# http://en.algoritmy.net/article/40379/Letter-frequency-English

english_freq = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  # A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  # H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  # O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074                     # V-Z
]

def getChi2 (s):
    count = [0]*26
    ignored = 0;

    for i in range(len(s)):
        c = ord(s[i])
        if c >= 65 and c <= 90:
            count[c - 65]+=1        # uppercase A-Z
        elif c >= 97 and c <= 122:
            count[c-97]+=1          # lowercase a-z
        elif c >= 32 and c <= 126:
            ignored+=1              # numbers and punct.
        elif c == 9 or c == 10 or c == 13:
            ignored+=1              # TAB, CR, LF
        else:
            return 10000000000     # not printable ASCII = impossible(?)
    

    chi2 = 0
    size = len(s) - ignored
    if ignored >= 0.25*len(s):
        return 10000000000 #ignored too much
    for i in range(26):
        observed = count[i]
        expected = size * english_freq[i]
        if expected == 0:
            return 10000000000
        difference = observed - expected
        chi2 += difference*difference / expected

    return chi2


def is_printable(s):
    return all(c in string.printable for c in s)


def xor(a,k):
    raw_a = a.decode("hex")
    return "".join([chr(ord(raw_a[i])^ord(k)) for i in range(len(raw_a))])


def brute(s):
    candidates = []
    for k in range(1,255):
        x = xor(s,chr(k))
        if is_printable(x):
            candidates.append((x,k,getChi2(x)))

    return candidates

with open("input_challenge04.txt") as f:
    INPUT = f.readlines()

    b = []
    for s in INPUT:
        b += brute(s.replace("\n",""))

b.sort(key = lambda x: x[2])

result = b[0][0]
key = b[0][1]
print result
print chr(key)

