#! /usr/bin/python3

# https://www.cryptopals.com/sets/4/challenges/29
# Break a SHA-1 keyed MAC using length extension

# SHA-1 implementation taken from https://github.com/ajalt/python-sha1/blob/master/sha1.py


################################################################################
### SHA-1 ######################################################################
################################################################################

import struct
import io


import sys 
sys.path.append('..')

from cryptopals import random_str

def _left_rotate(n, b):
    """Left rotate a 32-bit integer n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def _process_chunk(chunk, h0, h1, h2, h3, h4):
    """Process a chunk of data and return the new digest variables."""
    assert len(chunk) == 64
    #print "Chunk:",[chunk]
    #print "Process chunk [before]:",(hex(h0),hex(h1),hex(h2),hex(h3),hex(h4))
    w = [0] * 80

    # Break chunk into sixteen 4-byte big-endian words w[i]
    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]

    # Extend the sixteen 4-byte words into eighty 4-byte words
    for i in range(16, 80):
        w[i] = _left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    # Initialize hash value for this chunk
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    for i in range(80):
        if 0 <= i <= 19:
            # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                         a, _left_rotate(b, 30), c, d)

    # Add this chunk's hash to result so far
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff
    #print "Process chunk [after]:",(hex(h0),hex(h1),hex(h2),hex(h3),hex(h4))
    return h0, h1, h2, h3, h4


class Sha1Hash(object):
    """A class that mimics that hashlib api and implements the SHA-1 algorithm."""

    name = 'python-sha1'
    digest_size = 20
    block_size = 64

    def __init__(self,h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0,length_offset=0):
        # Initial digest variables
        self._h = (
            h0,
            h1,
            h2,
            h3,
            h4,
        )

        # bytes object with 0 <= len < 64 used to store the end of the message
        # if the message length is not congruent to 64
        self._unprocessed = b''
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = length_offset

    def update(self, arg):
        """Update the current digest.
        This may be called repeatedly, even after calling digest or hexdigest.
        Arguments:
            arg: bytes, bytearray, or BytesIO object to read from.
        """
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)
        # Try to build a chunk out of the unprocessed data, if any

        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        # Read the rest of the data, 64 bytes at a time
        while len(chunk) == 64:
            self._h = _process_chunk(chunk, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)


        self._unprocessed = chunk
        #print self._unprocessed
        return self

    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())

    def hexdigest(self):
        """Produce the final hash value (big-endian) as a hex string"""
        return '%08x%08x%08x%08x%08x' % self._produce_digest()

    def _produce_digest(self):
        """Return finalized digest variables for the data processed so far."""
        # Pre-processing:
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)

        # append the bit '1' to the message
        message += b'\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)
        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        message_bit_length = message_byte_length * 8
        #print message_bit_length
        message += struct.pack(b'>Q', message_bit_length)
        # Process the final chunk
        # At this point, the length of the message is either 64 or 128 bytes.
        h = _process_chunk(message[:64], *self._h)
        if len(message) == 64:
            #print (hex(h[0]),hex(h[1]),hex(h[2]),hex(h[3]),hex(h[4]))
            return h
        #print (hex(h[0]),hex(h[1]),hex(h[2]),hex(h[3]),hex(h[4]))
        return _process_chunk(message[64:], *h)


def sha1(data,h0=None,h1=None,h2=None,h3=None,h4=None,length_offset=0):
    """SHA-1 Hashing Function
    A custom SHA-1 hashing function implemented entirely in Python.
    Arguments:
        data: A bytes or BytesIO object containing the input message to hash.
    Returns:
        A hex SHA-1 digest of the input message.
    """
    if h0 and h1 and h2 and h3 and h4:
        return Sha1Hash(h0,h1,h2,h3,h4,length_offset).update(data).hexdigest()
    return Sha1Hash().update(data).hexdigest()

################################################################################
################################################################################

def MAC_SHA1(message,key):
    return sha1(key+message)

def fake_message(original_message,new_message,sha1_hash,min_key=0,max_key=40):
    possible_hashes = []
    h = [int(sha1_hash[0+i:8+i],16) for i in range(0,40,8)]
    #print "TEST:",map(hex,h)
    for i in range(min_key,max_key+1):
        temp = bytearray("A"*i,"ascii")
        temp.extend(original_message)
        pad = padding(temp)
        possible_hashes.append((original_message+pad+new_message,sha1(new_message,h[0],h[1],h[2],h[3],h[4],i+len(original_message)+len(pad))))
    return possible_hashes

def verify_mac_sha1(message,h):
    #print key
    return MAC_SHA1(message,key) == h

def padding(data):
    message_byte_length = len(data)

    # append the bit '1' to the message
    pad = bytearray([0x80])

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod 64)
    pad.extend(bytearray(((56 - (message_byte_length + 1) % 64) % 64)))
    message_bit_length = message_byte_length * 8
        #print message_bit_length
    pad.extend(struct.pack(b'>Q', message_bit_length))
    return pad

def main():
    global key
    key = random_str(10,40)
    message = bytearray("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon","ascii")
    #message = "A"
    mac = MAC_SHA1(message,key)

    new_message = bytearray(";admin=true","ascii")
    possible_hashes = fake_message(message,new_message,mac)

    for (m,h) in possible_hashes:
        if verify_mac_sha1(m,h):
            print (h)
            print (m)
            exit()

main()
