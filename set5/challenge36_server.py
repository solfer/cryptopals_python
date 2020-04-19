#! /usr/bin/python3

# https://www.cryptopals.com/sets/5/challenges/36
# Implement Secure Remote Password (SRP)
# Server

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

@app.route('/update', methods=['GET'])
def update_account():
    I = request.args.get('email')
    P = request.args.get('password')
    print(I,P)
    salt = randint(0,0xffffffff)
    xH = sha256(struct.pack('<I',salt)+bytearray(P, "ascii")).hexdigest()
    x = int(xH,16)
    v = pow(g,x,N)
    d[I] = {'salt':salt,'v':v}
    return "OK"

@app.route('/process', methods=['GET'])
def process():
    I = request.args.get('email')
    A = int(request.args.get('A'))

    b = randint(0,N)
    B = k*d[I]['v'] + pow(g,b,N)
    
    # Response
    r = str(d[I]['salt'])+';'+str(B)

    # Doing the next steps
    uH = sha256(int_to_bytes(A)+int_to_bytes(B)).hexdigest()
    u = int(uH,16)

    temp = pow(d[I]['v'],u,N)
    S = pow(A*temp,b,N)
    K = sha256(int_to_bytes(S)).digest()
    salt = struct.pack('<I',d[I]['salt'])
    hmac = HMAC_SHA256(K,salt)
    d[I]['hmac'] = hmac

    return r

@app.route('/verify', methods=['GET'])
def verify():
    I = request.args.get('email')
    hmac = request.args.get('hmac')
    if hmac == d[I]['hmac']:
        print("Succesfully verified")
        return "OK"
    print("Verification failed")
    return "FAIL"

# Waiting for email (I) and password (P):

# I and P received. Start processing


app.run()
