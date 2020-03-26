#! /usr/bin/python3 #INCOMPLETE

# https://www.cryptopals.com/sets/5/challenges/34
#Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

from random import randint
from Crypto.Cipher import AES

def main():

    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    #User A generates A
    a = randint(0,p)
    A = pow(g, a, p)

    #User A sends (p,g,A) to B
    b_data = (p,g,A)

    #User B generates B
    b = randint(0,b_data[0])
    B = pow(b_data[1], b, b_data[0])

    #User B sends B to A
    a_data = B

    #User A calculates s, iv, key and encrypt a message

    s_a = pow(a_data, a, p)
    iv_a = random_aes_key(16)
    msg_a = "Super Secret Stuff123"
    key_a = sha1(hex(s_a)[2:].replace('L','').decode('hex'))[:16]
    aes_ecb_a = AES.new(key_a, AES.MODE_ECB)
    enc_a = cbc_encrypt(aes_ecb_a, msg_a, iv_a)    
    #test = cbc_decrypt(aes_ecb_a, enc_a, iv_a)    
    #print test
    
    #User A sends encrypted message and iv to B
    b_data2 = enc_a+iv_a

    #User B calculates s, key, retrieves iv and decrypts the message:
    s_b = pow(b_data[2],b,p)
    #print s_a == s_b
    key_b = sha1(hex(s_b)[2:].replace('L','').decode('hex'))[:16]
    aes_ecb_b = AES.new(key_b, AES.MODE_ECB)
    msg_b = cbc_decrypt(aes_ecb_b,b_data2[:-16],b_data2[-16:])

    #User B generates an IV, encrypts the message retrieved and send it with the IV to A
    iv_b = random_aes_key(16)
    enc_b = cbc_encrypt(aes_ecb_b, msg_b, iv_b)
    
    a_data2 = enc_b+iv_b

    #A gets the iv, decrypts the data and verify the message:
    msg_temp = cbc_decrypt(aes_ecb_a,a_data2[:-16],a_data2[-16:])
    print (msg_a == msg_temp)


################################################################################
###### MITM attack 
################################################################################

    #User A generates A
    a = randint(0,p)
    A = pow(g, a, p)

    #User A sends (p,g,A) to M
    m_data = (p,g,A)

    #Use M send (p,g,p) to M
    b_data = (p,g,p)
    
    #User B generates B
    b = randint(0,b_data[0])
    B = pow(b_data[1], b, b_data[0])

    #User B sends B to M
    m_data2 = B
    a_data = p

    #User A calculates s, iv, key and encrypt a message

    s_a = pow(a_data, a, p)
    print (s_a)
    iv_a = random_aes_key(16)
    msg_a = "Super Secret Stuff123"
    print (hex(s_a))
    if s_a > 0xf:
        key_a = sha1(hex(s_a)[2:].replace('L','').decode('hex'))[:16]
    else:
        key_a = sha1(("0"+hex(s_a)[2:].replace('L','')).decode('hex'))[:16]
    aes_ecb_a = AES.new(key_a, AES.MODE_ECB)
    enc_a = cbc_encrypt(aes_ecb_a, msg_a, iv_a)    
    #test = cbc_decrypt(aes_ecb_a, enc_a, iv_a)    
    #print test
    
    #User A sends encrypted message and iv to M
    m_data3 = enc_a+iv_a

    #User M relays message to B
    b_data2 = m_data3

    #User B calculates s, key, retrieves iv and decrypts the message:
    s_b = pow(b_data[2],b,p)
    #print s_a == s_b
    if s_b > 0xf:
        key_b = sha1(hex(s_b)[2:].replace('L','').decode('hex'))[:16]
    else:
        key_b = sha1(("0"+hex(s_b)[2:].replace('L','')).decode('hex'))[:16]
    
    aes_ecb_b = AES.new(key_b, AES.MODE_ECB)
    msg_b = cbc_decrypt(aes_ecb_b,b_data2[:-16],b_data2[-16:])

    #User B generates an IV, encrypts the message retrieved and send it with the IV to M
    iv_b = random_aes_key(16)
    enc_b = cbc_encrypt(aes_ecb_b, msg_b, iv_b)
    
    m_data4 = enc_b+iv_b
    
    #User M relays message to A
    a_data2 = m_data4

    #A gets the iv, decrypts the data and verify the message:
    msg_temp = cbc_decrypt(aes_ecb_a,a_data2[:-16],a_data2[-16:])
    print (msg_a == msg_temp)



  

################################################################################
###### AES-CBC 
################################################################################

def random_str(start,stop):
    size = randint(start,stop)
    output = ""
    for i in range(size):
        output+=chr(randint(1,255))
    return output

def random_aes_key(x):
    return random_str(x,x)

def pkcs7_add(data, block_len=16):
    pad = block_len - len(data)%block_len
    if pad < 0:
        return None
    elif pad == 0:
        return data + chr(block_len)*block_len
    return data + chr(pad)*pad

def pkcs7_validation(data, block_len=16):
    pad_size = ord(data[-1])
    padding = data[-pad_size:]
    if len(set(padding)) != 1 or len(data)%block_len != 0:
        raise ValueError("Invalid padding")
        raise Exception("Bad padding")
    return data[:-pad_size]


def xor(a,b):
    raw_a = a
    raw_b = b
    return "".join([chr(ord(raw_a[i])^ord(raw_b[i])) for i in range(len(raw_a))])

def cbc_decrypt(aes_ecb,ciphertext, IV, BLOCK_LEN=16):
    blocks = [ciphertext[i:i+BLOCK_LEN] for i in range(0,len(ciphertext),BLOCK_LEN)]
    
    prev = IV
    plaintext = ""
    for block in blocks:
        dec = xor(aes_ecb.decrypt(block),prev)
        if block == blocks[-1]:
            plaintext += pkcs7_validation(dec)
        else:
            plaintext += dec
            prev = block
    return plaintext

def cbc_encrypt(aes_ecb,plaintext, IV, BLOCK_LEN=16):
    padded_plaintext = pkcs7_add(plaintext,BLOCK_LEN)
    blocks = [padded_plaintext[i:i+BLOCK_LEN] for i in range(0,len(padded_plaintext),BLOCK_LEN)]
    
    prev = IV
    ciphertext = ""
    for block in blocks:
        enc = aes_ecb.encrypt(xor(block,prev))
        ciphertext += enc
        prev = enc
    return ciphertext


# SHA-1 implementation taken from https://github.com/ajalt/python-sha1/blob/master/sha1.py


################################################################################
### SHA-1 ######################################################################
################################################################################

import struct
import io

try:
    range = xrange
except NameError:
    pass


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


main()
