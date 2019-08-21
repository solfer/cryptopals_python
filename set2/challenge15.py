#! /usr/bin/python

# https://www.cryptopals.com/sets/2/challenges/15
# PKCS#7 padding validation




def pkcs7_add(data, block_len=16):
    pad = block_len - len(data)%block_len
    if pad < 0:
        return None
    elif pad == 0:
        return data + chr(block_len)*block_len
    return data + chr(pad)*pad

def pkcs7_remove(data):
    pad = ord(data[-1])
    return data[:-pad]

def pkcs7_validation(data, block_len=16):
    pad_size = ord(data[-1])
    padding = data[-pad_size:]
    if len(set(padding)) != 1 or len(data)%block_len != 0:
        raise ValueError("Invalid padding")
        raise Exception("Bad padding")
    return data[:-pad_size]
        

def main():

    INPUT1 = "ICE ICE BABY\x04\x04\x04\x04"
    INPUT2 = "ICE ICE BABY\x05\x05\x05\x05"
    INPUT3 = "ICE ICE BABY\x01\x02\x03\x04"

    inputs = [INPUT1,INPUT2,INPUT3]

    for i in inputs:
        try:
            print pkcs7_validation(i)
        except Exception as error:
            print repr(error)
            

main()
