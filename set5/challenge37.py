#! /usr/bin/python3

# https://www.cryptopals.com/sets/5/challenges/37
# Break SRP with a zero key
# Use the server implemented for challenge36 (challenge36_server.py)

from random import randint
from hashlib import sha256
import struct
import requests

import sys 
sys.path.append('..')

from cryptopals import int_to_bytes,HMAC_SHA256

# Constants
N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3

I = "bob@bob.com"
P = "bla"

if (False):
    # Creating account
    query = f"http://127.0.0.1:5000/update?email={I}&password={P}"
    r = requests.get(query)

    if r.text != "OK":
        print("Something went wrong!!!")
        exit()

# Erasing password
P = ""

# Attack 1: A = 0

A = 0
# This will force S = 0 (easily observer in the server code)

query = f"http://127.0.0.1:5000/process?email={I}&A={A}"
r = requests.get(query)
temp = r.text.split(';')

salt = int(temp[0])
B = int(temp[1])

S = 0
K = sha256(int_to_bytes(S)).digest()
hmac = HMAC_SHA256(K,struct.pack('<I',salt))

query = f"http://127.0.0.1:5000/verify?email={I}&hmac={hmac}"
r = requests.get(query)
print ("A = 0",r.text)

# Attack 2: sending multiples of N (I could have included 0 here)

for i in range(1,11):
    A = N*i
    # This will force S = 0 (easily observer in the server code - S will be a multiple of N)

    query = f"http://127.0.0.1:5000/process?email={I}&A={A}"
    r = requests.get(query)
    temp = r.text.split(';')

    salt = int(temp[0])
    B = int(temp[1])

    S = 0
    K = sha256(int_to_bytes(S)).digest()
    hmac = HMAC_SHA256(K,struct.pack('<I',salt))

    query = f"http://127.0.0.1:5000/verify?email={I}&hmac={hmac}"
    r = requests.get(query)
    print (f"A = N*{i}",r.text)


