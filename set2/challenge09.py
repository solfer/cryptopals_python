#! /usr/bin/python

# https://www.cryptopals.com/sets/2/challenges/9
# Implement PKCS#7 padding

def pkcs7(data, block_len):
    pad = block_len - len(data)
    if pad < 0:
        return None
    elif pad == 0:
        return data + chr(block_len)*block_len
    return data + chr(pad)*pad


def main():

    INPUT = "YELLOW SUBMARINE"
    RESULT = "YELLOW SUBMARINE\x04\x04\x04\x04"

    result = pkcs7(INPUT,20)

    print "Success" if RESULT == result else "Fail"

main()
