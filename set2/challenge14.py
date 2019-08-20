#! /usr/bin/python

from Crypto.Cipher import AES

from random import randint

# https://www.cryptopals.com/sets/2/challenges/14
# Byte-at-a-time ECB decryption (Harder)


def detect_ecb(cipher):
    blocks = [cipher[i*16:(i+1)*16] for i in range(0,len(cipher)/16)]
    x = len(blocks)
    y = len(set(blocks))

    return not x==y


def random_aes_key(x):
    return random_str(x,x)

def random_str(start,stop):
    size = randint(start,stop)
    output = ""
    for i in range(size):
        output+=chr(randint(1,255))
    return output
    
def encryption_oracle(plaintext):
    global random_string
    block_len = 16
    key = KEY
    aes_ecb = AES.new(key, AES.MODE_ECB)

    unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".decode("base64")
    data = random_string+plaintext+unknown


    data = pkcs7_add(data,block_len)
    test = aes_ecb.encrypt(data)

    return test    



def pkcs7_add(data, block_len):
    pad = block_len - len(data)%block_len
    if pad < 0:
        return None
    elif pad == 0:
        return data + chr(block_len)*block_len
    return data + chr(pad)*pad

def pkcs7_remove(data):
    pad = ord(data[-1])
    return data[:-pad]

def main():
    
    global random_string #Lazy me

    random_string = random_str(1,32*4)
    #Detecting block size
    a = len(encryption_oracle("A"))
    for i in range(2,40):
        b = len(encryption_oracle("A"*i))
        if a != b:
            blocksize = b-a
            print "Block size: %d bytes" %(blocksize,)
            break
        
    #Detecting ECB: #Not needed. Here for the lolz
    for i in range(blocksize,3*blocksize):
        if detect_ecb(encryption_oracle("A"*i)):
            print "ECB detected"
            break

    #Detecting size of the random string
    for i in range(blocksize,3*blocksize):
        cipher = encryption_oracle("A"*i)
        if detect_ecb(cipher): #Lazy me again.
            blocks = [cipher[j*16:(j+1)*16] for j in range(0,len(cipher)/16)]
            for j in range(1,len(blocks)):
                if blocks[j] == blocks[j+1]:
                    size_random_string = (j)*blocksize - i%blocksize
                    break
            break

    print "Size of random string:", size_random_string
    offset = (-size_random_string % blocksize)
    padding = "X"*offset
    print "Length of padding:", len(padding),"\n"

    #Retrieving unknown text:
    table = [encryption_oracle(padding+"B"*(blocksize-i)) for i in range(1,blocksize+1)]

    secret = ""
    skip = (offset+size_random_string)/blocksize
    for j in range(skip,len(table[-1])):
        for i in range(1,blocksize+1):
            cipher = table[i-1][j*blocksize:(j+1)*blocksize]
            for c in range(256):
                temp = encryption_oracle(padding+"B"*(blocksize-i)+secret+chr(c))[j*blocksize:(j+1)*blocksize]
                if temp == cipher:
                    secret += chr(c)
                    break
    print secret

KEY = random_aes_key(16)
main()
