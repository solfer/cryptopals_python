#! /usr/bin/python

from Crypto.Cipher import AES
import struct

# https://www.cryptopals.com/sets/2/challenges/18
# Implement CTR, the stream cipher mode

def ctr(data,key,nonce,blocksize=16):
    aes = AES.new(key, AES.MODE_ECB)
    nonce = struct.pack("<Q",nonce) #unsigned LE long long int (8 bytes)
    count = 0
    ciphertext = bytearray(data)

    for i in range((len(ciphertext))):
        if i % blocksize == 0:
            keystream = aes.encrypt(nonce+struct.pack("<q",count)) #signed LE long long int (8 bytes)
            count += 1
        ciphertext[i] ^= ord(keystream[i % blocksize])

    return str(ciphertext)

def main():
    key = "YELLOW SUBMARINE"
    INPUT = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    nonce = 0

    data = INPUT.decode("base64")

    print ctr(data,key,nonce)

main()
