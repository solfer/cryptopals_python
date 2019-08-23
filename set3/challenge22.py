#! /usr/bin/python

# https://www.cryptopals.com/sets/2/challenges/22
# Crack an MT19937 seed

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


def main():
    s_time = int(time.time())

    seed_mt(0)
    seed = s_time + 40 + (extract_number()%1000) #I'm using my implementation to fake the passage of time
    
    seed_mt(seed)
    output = extract_number()

    print "RNG output:", output
    print "Seed used:", seed

    seed_mt(17)
    current_time = int(time.time()) + (50 + extract_number()%1000) #Faking time again

    t = 2000
    for s in range(current_time - t,current_time+1):
         seed_mt(s)
         if output == extract_number():
            print "Seed detected:", s
            break
    

main()
