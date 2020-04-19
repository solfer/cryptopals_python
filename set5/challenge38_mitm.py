#! /usr/bin/python3

# https://www.cryptopals.com/sets/5/challenges/38
# Implement Secure Remote Password (SRP)
# MITM

from random import randint
from hashlib import sha256
import struct

import sys 
sys.path.append('..')

from cryptopals import int_to_bytes,HMAC_SHA256

# Constants
N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3

# "database"
d = {}

from flask import Flask,request

#start
app = Flask(__name__)

@app.route('/query', methods=['GET'])
def query():
    print(d)
    return "COOL"

@app.route('/process', methods=['GET'])
def fake_process():
    I = request.args.get('email')
    A = int(request.args.get('A'))

    salt = randint(0,0xFFFFFFFF)
    b = randint(0,N)
    B = pow(g,b,N)
    u = randint(1,0xFFFFFFFFFFFFFFFF)
    d[I] = {'salt':salt,'b':b,'B':B,'u':u,'A':A}
    # Response
    r = str(salt)+';'+str(B)+';'+str(u)
    return r

@app.route('/verify', methods=['GET'])
def fake_verify():
    I = request.args.get('email')
    hmac = request.args.get('hmac')
    
    A = d[I]['A']
    b = d[I]['b']
    u = d[I]['u']
    salt = struct.pack('<I',d[I]['salt'])
    wordlist = "/usr/share/wordlists/dirb/others/best1050.txt"
    with open(wordlist,'r') as f:
        w = f.read().splitlines()

    for P in w:
        xH = sha256(salt+bytearray(P, "ascii")).hexdigest()
        x = int(xH,16)
        v = pow(g,x,N)
        temp = pow(v,u,N)
        S = pow(A*temp,b,N)
        K = sha256(int_to_bytes(S)).digest()

        if HMAC_SHA256(K,salt) == hmac:
            print("CRACKED!!!!")
            print(P)
            return P

app.run(port=6666)
