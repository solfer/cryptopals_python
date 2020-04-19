#! /usr/bin/python3

# https://www.cryptopals.com/sets/5/challenges/36
# Implement Secure Remote Password (SRP)
# Client

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

# Creating account
wordlist = "/usr/share/wordlists/dirb/others/best1050.txt"
I = "bob@bob.com"
with open(wordlist,'r') as f:
    w = f.read().splitlines()

P = w[randint(0,len(w)-1)]

query = f"http://127.0.0.1:5000/update?email={I}&password={P}"
r = requests.get(query)

if r.text != "OK":
    print("Something went wrong!!!")
    exit()

#requests.get("http://127.0.0.1:5000/query")

# Legitimate server
a = randint(0,N)
A = pow(g,a,N)
query = f"http://127.0.0.1:5000/process?email={I}&A={A}"
r = requests.get(query)
temp = r.text.split(';')

salt = int(temp[0])
B = int(temp[1])
u = int(temp[2])

xH = sha256(struct.pack('<I',salt)+bytearray(P, "ascii")).hexdigest()
x = int(xH,16)

S = pow(B,a+(u*x),N)
K = sha256(int_to_bytes(S)).digest()
hmac = HMAC_SHA256(K,struct.pack('<I',salt))

query = f"http://127.0.0.1:5000/verify?email={I}&hmac={hmac}"
r = requests.get(query)
print ("Response from legitimate server:",r.text)


# Fake server
query = f"http://127.0.0.1:6666/process?email={I}&A={A}"
r = requests.get(query)
temp = r.text.split(';')

salt = int(temp[0])
B = int(temp[1])
u = int(temp[2])

xH = sha256(struct.pack('<I',salt)+bytearray(P, "ascii")).hexdigest()
x = int(xH,16)

S = pow(B,a+(u*x),N)
K = sha256(int_to_bytes(S)).digest()
hmac = HMAC_SHA256(K,struct.pack('<I',salt))

query = f"http://127.0.0.1:6666/verify?email={I}&hmac={hmac}"
r = requests.get(query)
print ("Original password:",P)
print ("Cracked password :",r.text)
