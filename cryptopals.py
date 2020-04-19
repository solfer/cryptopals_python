# receives to bytearrays and returns a bytearray
def xor(a,b):
    return bytearray([a[i]^b[i] for i in range(len(a))])

# receives the hex representation of 2 variables and returns a bytearray
def xor_hex(a,b):
    raw_a = bytearray.fromhex(a)
    raw_b = bytearray.fromhex(b)
    return xor(raw_a,raw_b)

# receives the hex representation of a variable and a constant (int) and returns a bytearray
def xor_hex_constant(a,k):
    raw_a = bytearray.fromhex(a)
    raw_b = bytearray([k]*len(raw_a))
    return xor(raw_a,raw_b)

def xor_str_constant(a,k):
    raw_a = bytearray(a,"ascii")
    raw_b = bytearray([k]*len(raw_a))
    return xor(raw_a,raw_b)

def xor_str_cyclic(a,b):
    if len(a) < len (b):
        a,b = b,a
    raw_a = bytearray(a,"ascii")
    raw_b = bytearray(b,"ascii")
    xored = bytearray([raw_a[i]^raw_b[i%len(raw_b)] for i in range(len(raw_a))])
    return xored

## https://crypto.stackexchange.com/questions/30209/developing-algorithm-for-detecting-plain-text-via-frequency-analysis
# http://en.algoritmy.net/article/40379/Letter-frequency-English

english_freq = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  # A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  # H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  # O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074                     # V-Z
]

#TODO Merge with getChi2_space
def getChi2 (s):
    count = [0]*26
    ignored = 0;

    for i in range(len(s)):
        c = s[i]
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

## https://crypto.stackexchange.com/questions/30209/developing-algorithm-for-detecting-plain-text-via-frequency-analysis
# http://www.macfreek.nl/memory/Letter_Distribution



#TODO: Replace this with a dictionary
english_freq_space = [
    0.0653216702, 0.0125888074, 0.0223367596, 0.0328292310, 0.1026665037, 0.0198306716, 0.0162490441,  # A-G
    0.0497856396, 0.0566844326, 0.0009752181, 0.0056096272, 0.0331754796, 0.0202656783, 0.0571201113,  # H-N
    0.0615957725, 0.0150432428, 0.0008367550, 0.0498790855, 0.0531700534, 0.0751699827, 0.0227579536,  # O-U
    0.0079611644, 0.0170389377, 0.0014092016, 0.0142766662, 0.0005128469, 0.1828846265                  # V-Z+space
]

def getChi2_space (s):
    count = [0]*27
    ignored = 0

    for i in range(len(s)):
        c = s[i]
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
        expected = size * english_freq_space[i]
        if expected == 0:
            return 10000000000
        difference = observed - expected
        chi2 += difference*difference / expected

    return chi2


def is_printable(s):
    import string
    return all(c in string.printable for c in str(s))

def detect_ecb(cipher,block_len=16):
    blocks = [bytes(cipher[i*block_len:(i+1)*block_len]) for i in range(0,int(len(cipher)/block_len))] #setting it to bytes because bytearray is unhashable
    x = len(blocks)
    y = len(set(blocks))

    return not x==y


#Receives a bytearray
def pkcs7_add(data, block_len):
    out = bytearray(data)
    pad = block_len - len(out)%block_len
    if pad < 0:
        return None
    elif pad == 0:
        out.extend(bytes([block_len]*block_len))
        return out
    out.extend(bytes([pad]*pad))
    return out

def pkcs7_remove(data):
    pad = data[-1]
    return data[:-pad]

# plaintext is a bytearray
def cbc_encrypt(aes_ecb,plaintext,IV,block_len=16):
    padded_plaintext = pkcs7_add(bytes(plaintext),block_len)
    blocks = [bytes(padded_plaintext[i:i+block_len]) for i in range(0,len(padded_plaintext),block_len)]
    prev = IV
    ciphertext = bytearray()
    for block in blocks:
        enc = aes_ecb.encrypt(bytes(xor(block,prev)))
        ciphertext.extend(enc)
        prev = enc
    return ciphertext

# ciphertext is a bytearray and iv's type is bytes 
def cbc_decrypt(aes_ecb,ciphertext,IV,block_len=16,validation=False):

    blocks = [bytes(ciphertext[i:i+block_len]) for i in range(0,len(ciphertext),block_len)]
    prev = IV
    plaintext = bytearray()
    for block in blocks:

        dec = aes_ecb.decrypt(block)
        plaintext.extend(xor(dec,prev))
        prev = block

    if validation:
        plaintext = pkcs7_validation(plaintext)
    return plaintext

def random_aes_key(x=16):
    return random_str(x,x)

def random_str(start,stop):
    from random import randint
    size = randint(start,stop)
    return bytes([randint(0,255) for i in range(size)])

def pkcs7_validation(data, block_len=16):
    pad_size = data[-1]
    padding = data[-pad_size:]
    if len(set(padding)) != 1 or len(data)%block_len != 0:
        raise ValueError("Invalid padding")
        raise Exception("Bad padding")
    return data[:-pad_size]

def ctr(data,key,nonce,blocksize=16):
    from Crypto.Cipher import AES
    import struct
    aes = AES.new(key, AES.MODE_ECB)
    nonce = struct.pack("<Q",nonce) #unsigned LE long long int (8 bytes)
    count = 0
    ciphertext = bytearray(data)

    for i in range((len(ciphertext))):
        if i % blocksize == 0:
            keystream = aes.encrypt(nonce+struct.pack("<q",count)) #signed LE long long int (8 bytes)
            count += 1
        ciphertext[i] ^= keystream[i % blocksize]

    return ciphertext

# SHA-1 implementation taken from https://github.com/ajalt/python-sha1/blob/master/sha1.py

################################################################################
### SHA-1 ######################################################################
################################################################################

import struct
import io

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


def int_to_bytes(x,order="little"):
    from math import log2
    if x == 0:
        return b'\x00'
    return x.to_bytes(int(log2(x)/8)+1, byteorder=order, signed=False)


def HMAC_SHA256(data,k,blocksize=64):
    from hashlib import sha256
    if len(k) > blocksize:
        k = int_to_bytes(int(sha256(k).hexdigest(),16))

    if len(k) < blocksize:
        k += bytes(blocksize-len(k))
    
    o_key_pad = xor(k,b"\x5c"*blocksize)
    i_key_pad = xor(k,b"\x36"*blocksize)

    temp = int_to_bytes(int(sha256(i_key_pad + data).hexdigest(),16))
    h = sha256(o_key_pad+temp).hexdigest()
    return h

# https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
# I haven't tested this properly
def xgcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

def modinv(a, b):
    """return x such that (x * a) % b == 1"""
    g, x, _ = xgcd(a, b)
    if g != 1:
        raise Exception(f'gcd({a}, {b}) != 1')
    return x % b

def rsa_encrypt(m,e,n):
    return pow(m,e,n)

def rsa_decrypt(c,d,n):
    return rsa_encrypt(c,d,n) #lol

def rsa_key_gen(p,q,e):
    n = p*q
    et = (p-1)*(q-1)
    d = modinv(e,et)
    pub_key = (e,n)
    priv_key = (d,n)
    return (pub_key,priv_key)

def test_primes(p,q,e):
    et = (p-1)*(q-1)
    try:
        modinv(e,et)
        return True
    except:
        return False

def generate_rsa_prime():
    import os
    return int(os.popen("openssl prime -generate -bits 2048").read())


