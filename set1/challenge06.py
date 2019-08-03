#! /usr/bin/python

# https://www.cryptopals.com/sets/1/challenges/6
# Break repeating-key XOR

# wget https://www.cryptopals.com/static/challenge-data/6.txt --no-check-certificate

## https://crypto.stackexchange.com/questions/30209/developing-algorithm-for-detecting-plain-text-via-frequency-analysis
# http://www.macfreek.nl/memory/Letter_Distribution

#TODO: Replace this with a dictionary
english_freq = [
    0.0653216702, 0.0125888074, 0.0223367596, 0.0328292310, 0.1026665037, 0.0198306716, 0.0162490441,  # A-G
    0.0497856396, 0.0566844326, 0.0009752181, 0.0056096272, 0.0331754796, 0.0202656783, 0.0571201113,  # H-N
    0.0615957725, 0.0150432428, 0.0008367550, 0.0498790855, 0.0531700534, 0.0751699827, 0.0227579536,  # O-U
    0.0079611644, 0.0170389377, 0.0014092016, 0.0142766662, 0.0005128469, 0.1828846265                  # V-Z+space
]

def getChi2 (s):
    count = [0]*27
    ignored = 0

    for i in range(len(s)):
        c = ord(s[i])
        if c >= 65 and c <= 90:
            count[c - 65]+=1        # uppercase A-Z
        elif c >= 97 and c <= 122:
            count[c-97]+=1          # lowercase a-z
        elif c == 0x20:             # space
            count[26]+=1
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
    for i in range(27):
        observed = count[i]
        expected = size * english_freq[i]
        if expected == 0:
            return 10000000000
        difference = observed - expected
        chi2 += difference*difference / expected

    return chi2


def xor(a,k):
    raw_a = a
    return "".join([chr(ord(raw_a[i])^ord(k)) for i in range(len(raw_a))])


def brute(s):
    candidates = []
    for k in range(0,256):
        x = xor(s,chr(k))

        candidates.append((x,chr(k),getChi2(x)))
    return candidates



def hamming_distance(s1,s2):
    if len(s1) != len(s2):
        return None
    return sum([bin(ord(s1[i])^ord(s2[i])).count("1") for i in range(len(s1))])


def xor_cyclic(a,b):
    return "".join([chr(ord(a[i])^ord(b[i%len(b)])) for i in range(len(a))]).encode("hex")

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
    #print hamming_distance("this is a test","wokka wokka!!!") # should be 37

    #Hamming distance works fine

    with open("6.txt") as f:
        INPUT = "".join(f.readlines()).replace("\n","").decode("base64")

    #Input being decoded correctly

    dists = key_candidates(INPUT)

    keysizes = [i[0] for i in dists[:6]]   #Getting the 6 most likely candidates
    
    possible_keys = []
    for KEYSIZE in keysizes:
        blocks = [INPUT[i*KEYSIZE:(i+1)*KEYSIZE] for i in range(1+len(INPUT)/KEYSIZE)]
        t_blocks = [""]*KEYSIZE

        for block in blocks:
            for i in range(len(block)): #not using KEYSIZE because I'm lazy
                t_blocks[i] += block[i]
        
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
        print "Decrypting using \"%s\"\n" %(key,)
        for i,c in enumerate(INPUT):
             decrypted+=chr(ord(c)^ord(key[i%len(key)]))
        print decrypted

main()
