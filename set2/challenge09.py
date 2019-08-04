#! /usr/bin/python

# https://www.cryptopals.com/sets/2/challenges/9
# Implement PKCS#7 padding


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

    INPUT = "YELLOW SUBMARINE"
    RESULT = "YELLOW SUBMARINE\x04\x04\x04\x04"

    result = pkcs7_add(INPUT,20)

    print "Success" if RESULT == result else "Fail"

main()
