#! /usr/bin/python3

# https://www.cryptopals.com/sets/2/challenges/15
# PKCS#7 padding validation

import sys 
sys.path.append('..')

from cryptopals import pkcs7_validation
   

def main():

    INPUT1 = "ICE ICE BABY\x04\x04\x04\x04"
    INPUT2 = "ICE ICE BABY\x05\x05\x05\x05"
    INPUT3 = "ICE ICE BABY\x01\x02\x03\x04"

    inputs = [INPUT1,INPUT2,INPUT3]

    for i in inputs:
        try:
            print (pkcs7_validation(bytearray(i,'ascii')))
        except Exception as error:
            print (repr(error))
            

main()
