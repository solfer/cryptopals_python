#! /usr/bin/python

# https://www.cryptopals.com/sets/4/challenges/30
# Break an MD4 keyed MAC using length extension

# MD4 implementation taken from https://gist.github.com/bonsaiviking/5644414


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
        for r in xrange(16):
            i = (16-r)%4
            k = r
            h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
        # Round 2
        s = (3,5,9,13)
        for r in xrange(16):
            i = (16-r)%4 
            k = 4*(r%4) + r//4
            h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in xrange(16):
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
        for chunk in xrange(0, len(message)-r, 64):
            self._add_chunk( message[chunk:chunk+64] )
        return self

    def finish(self):
        l = len(self.remainder) + 64 * self.count
        #print "l:",l
        self.add( "\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8) )
        out = struct.pack("<4I", *self.h)
        self.__init__() #reset all the changes
        return out.encode("hex")

def main_debug():
    global key
    key = "bob"
    test = (
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"),
            ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536")
        )

    print MD4("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x80\xb8\x01\x00\x00\x00\x00\x00\x00A").finish()
    print MD4("A",0x52b17b1d, 0xcabd1484, 0x10d509b7, 0x886d767f,64).finish()
    #8746b6c886ef5ffc88818c6f9a6b56ba
    #print MD4("a").finish()
    #message = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    message = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    hx = MD4(message).finish()
    h = struct.unpack("<4I", hx.decode("hex"))
    print h
    print "FAKE HASH:",hx
    #message = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x80\xb8\x01\x00\x00\x00\x00\x00\x00A"


    pad = padding(message)
    data = message+pad+"A"
    print "DATA:",[data]
    hx = MD4(data).finish()
    #h = [int(hx[i:i+8],16) for i in range(0,32,8)]
    print "GOAL:",hx
    print "XXXXX"
    new_message = "A"
    print "fake:",h[0],h[1],hex(h[2]),hex(h[3])
    print "0x52b17b1d, 0xcabd1484, 0x10d509b7, 0x886d767f"
    hx2 = MD4(new_message,h[0], h[1], h[2], h[3],64).finish()
    #hx2 = MD4(new_message,h[0], h[1], h[2], h[3],64).finish()
    #M: ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x80\xb8\x01\x00\x00\x00\x00\x00\x00']
    #['0x52b17b1d', '0xcabd1484', '0x10d509b7', '0x886d767f']
    print hx2
    
    message = "a"
    h = MAC_MD4(message,key)
    new_message = "BRO"
    print "======="
    possible_hashes = fake_message(message,new_message,h,3,3)
    #exit()
    for (m,h) in possible_hashes:
        print "bazinga:",[m]
        if verify_mac_md4(m,h):
            print h,"\n"
            print [m]
            exit()
    exit()
    md = MD4()
    for t, h in test:
        md.add(t)
        d = md.finish()
        if d == h:
            print "pass"
            #print "Pad:",[padding(t)]
        else:
            print "FAIL: {0}: {1}\n\texpected: {2}".format(t, d.encode("hex"), h)


################################################################################
################################################################################

def MAC_MD4(message,key):
    md = MD4(key+message)
    return md.finish()

def fake_message(original_message,new_message,md4_hash,min_key=0,max_key=40):
    possible_hashes = []
    h = struct.unpack("<4I", md4_hash.decode("hex"))
    for i in range(min_key,max_key+1):
        pad = padding("A"*i+original_message)
        MD4("A"*i+original_message)
        possible_hashes.append((original_message+pad+new_message,MD4(new_message,h[0],h[1],h[2],h[3],i+len(original_message)+len(pad)).finish()))
    return possible_hashes

def verify_mac_md4(message,h):
    x = MAC_MD4(message,key)
    return x == h

def padding(data):
    return "\x80" + "\x00" * ((55 - len(data)) % 64) + struct.pack("<Q", len(data) * 8) 

def main():
    global key
    key = "bob"
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = MAC_MD4(message,key)

    new_message = ";admin=true"
    possible_hashes = fake_message(message,new_message,mac)

    for (m,h) in possible_hashes:
        if verify_mac_md4(m,h):
            print h,"\n"
            print [m]
            exit()

main()
