#! /usr/bin/python

# https://www.cryptopals.com/sets/2/challenges/23
# Clone an MT19937 RNG from its output

import time

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
        MT[i] = ((1 << w) -1) & (f * (MT[i-1] ^ (MT[i-1] >> (w-2)))+i) & d
 

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

def fake_extract_number():
    global fake_index
    if fake_index >= n:
        fake_twist()
        
    y = fake_MT[fake_index]
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)
    fake_index += 1
    return ((1 << w) -1) & y #return lowest w bits of y


def unextractor(fy):

#(w, n, m, r) = (32, 624, 397, 31)
#a = 0x9908B0DF
#(u,d) = (11,0xFFFFFFFF)
#(s,b) = (7, 0x9D2C5680) # 0b10011101001011000101011010000000
#(t, c) = (15, 0xEFC60000)
#l = 18

    
    #The 18 (l) most signicant bits are the same as the ones from the original y
    fy = fy ^ (fy >> (l) & d) #18 most significant bits (&d because I don't know how python handles signed(?!?!) integers)

    fy = fy ^ ((fy << t) & c) # I wasn't 100% sure and verified by exhausting the keyspace

    #I could use a loop or something decent but it works
    temp_a = fy & 0x7F
    temp_b = ((fy >> 7) ^ (temp_a & (b>>7)))& 0x7F
    temp_c = ((fy >> 14) ^ (temp_b & (b>>14))) & 0x7F
    temp_d = ((fy >> 21) ^ (temp_c & (b>>21))) & 0x7F
    temp_e = ((fy >> 28) ^ (temp_d & (b>>28))) & 0x7F
    fy = (temp_e << 28) + (temp_d << 21) + (temp_c << 14) + (temp_b << 7) + temp_a

    temp_a = ((fy >> 11) ^ fy) & 0xfffff800
    temp_b = (fy ^ ((temp_a >> 11) & 0x7ff))& 0x7ff
    fy = temp_a + temp_b

    return fy
    #index += 1
    return ((1 << w) -1) & y #return lowest w bits of y
    

# Generate the next n values from the series x_i
def twist():
    global n
    global index
    global MT
    for i in range(0,n):
        x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
        xA = (x >> 1) & d
        if x % 2 != 0: #lowest bit of x is 1
            xA = xA ^ a

        MT[i] = MT[(i+m) % n] ^ xA
    index = 0

# Generate the next n values from the series x_i
def fake_twist():
    global n
    global fake_index
    global fake_MT
    for i in range(0,n):
        x = (fake_MT[i] & upper_mask) + (fake_MT[(i+1) % n] & lower_mask)
        xA = (x >> 1) & d
        if x % 2 != 0: #lowest bit of x is 1
            xA = xA ^ a

        fake_MT[i] = fake_MT[(i+m) % n] ^ xA
    fake_index = 0


def main():
    seed_mt(0)
    retrieved = []
    for i in range(n):
        retrieved.append(extract_number())

    reversed_states = []
    for i in range(n):
        reversed_states.append(unextractor(retrieved[i]))
    
    global fake_MT
    global fake_index
    fake_MT = reversed_states
    fake_index = n

    print MT == fake_MT

    print extract_number()
    print fake_extract_number()

main()
