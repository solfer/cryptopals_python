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
    pad = block_len - len(data)%block_len
    if pad < 0:
        return None
    elif pad == 0:
        data.extend(bytes([block_len]*block_len))
        return data
    data.extend(bytes([pad]*pad))
    return data

def pkcs7_remove(data):
    pad = data[-1]
    return data[:-pad]

def cbc_encrypt(aes_ecb,plaintext,IV,BLOCK_LEN=16):
    blocks = [bytes(plaintext[i:i+BLOCK_LEN]) for i in range(0,len(plaintext),BLOCK_LEN)]
    
    prev = IV
    ciphertext = bytearray()
    for block in blocks:
        if len(block) != BLOCK_LEN:
            block = pkcs7_add(bytearray(block),BLOCK_LEN)
        enc = aes_ecb.encrypt(bytes(xor(block,prev)))
        ciphertext.extend(xor(enc,prev))
        prev = enc
    return ciphertext

def cbc_decrypt(aes_ecb,ciphertext,IV,block_len=16):
    blocks = [bytes(ciphertext[i:i+block_len]) for i in range(0,len(ciphertext),block_len)]
    
    prev = bytes(IV,"ascii")
    plaintext = bytearray()
    for block in blocks:
        dec = aes_ecb.decrypt(block)
        plaintext.extend(xor(dec,prev))
        prev = block
    return plaintext

def random_aes_key(x):
    return random_str(x,x)

def random_str(start,stop):
    from random import randint
    size = randint(start,stop)
    return bytes([randint(0,255) for i in range(size)])
