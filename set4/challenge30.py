#! /usr/bin/python3

# https://www.cryptopals.com/sets/4/challenges/30
# Break an MD4 keyed MAC using length extension

# MD4 implementation taken from https://gist.github.com/bonsaiviking/5644414

import sys 
sys.path.append('..')

from cryptopals import random_str

################################################################################
### MD4 ########################################################################
################################################################################
import struct

def leftrotate(i, n):
    return ((i << n) & 0xffffffff) | (i >> (32 - n))

def F(x,y,z):
    return (x & y) | (~x & z)

def G(x,y,z):
    return (x & y) | (x & z) | (y & z)

def H(x,y,z):
    return x ^ y ^ z

class MD4(object):
    def __init__(self, data="", h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476,length_offset=0):
        self.remainder = data
        self.count = length_offset/64
        self.h = [h0, h1, h2, h3]

    def _add_chunk(self, chunk):
        self.count += 1
        X = list( struct.unpack("<16I", chunk) + (None,) * (80-16) )
        h = [x for x in self.h]
        # Round 1
        s = (3,7,11,19)
        for r in range(16):
            i = (16-r)%4
            k = r
            h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
        # Round 2
        s = (3,5,9,13)
        for r in range(16):
            i = (16-r)%4 
            k = 4*(r%4) + r//4
            h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in range(16):
            i = (16-r)%4 
            h[i] = leftrotate( (h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )

        for i,v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2**32

    def add(self, data):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = ""
        for chunk in range(0, len(message)-r, 64):
            self._add_chunk( message[chunk:chunk+64] )
        return self

    def finish(self):
        l = int(len(self.remainder) + 64 * self.count)

        #print "l:",l
        temp = bytearray([0x80])
        temp.extend(bytearray((55 - l) % 64))
        temp.extend(struct.pack("<Q", l * 8))
        self.add(temp)
        out = struct.pack("<4I", *self.h)
        self.__init__() #reset all the changes
        return out.hex()

################################################################################
################################################################################

def MAC_MD4(message,key):
    md = MD4(key+message)
    return md.finish()

def fake_message(original_message,new_message,md4_hash,min_key=0,max_key=40):
    possible_hashes = []
    h = struct.unpack("<4I", bytes.fromhex(md4_hash))
    for i in range(min_key,max_key+1):
        temp = bytearray("A"*i,"ascii")
        temp.extend(original_message)
        pad = padding(temp)
        possible_hashes.append((original_message+pad+new_message,MD4(new_message,h[0],h[1],h[2],h[3],i+len(original_message)+len(pad)).finish()))
    return possible_hashes

def verify_mac_md4(message,h):
    x = MAC_MD4(message,key)
    return x == h

def padding(data):
    pad = bytearray([0x80])
    pad.extend(bytearray((55 - len(data)) % 64))
    pad.extend(struct.pack("<Q", len(data) * 8))
    return pad

def main():
    global key
    key = random_str(10,40)
    key = bytearray("bob","ascii")
    message = bytearray("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon","ascii")
    mac = MAC_MD4(message,key)

    new_message = bytearray(";admin=true","ascii")
    possible_hashes = fake_message(message,new_message,mac)

    for (m,h) in possible_hashes:
        if verify_mac_md4(m,h):
            print (h)
            print (m)
            exit()
main()
