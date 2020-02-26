#! /usr/bin/python

# https://www.cryptopals.com/sets/5/challenges/37
# Break SRP with a zero key

from random import randint

from hashlib import sha256

import requests

import sys

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

p = N
g = 2

k = 3

I = "bob@example.com"

P = "SuperSecretP@ss123!"

            

def main():

    server = init_server()

    a = randint(0,N)
    A = pow(g,a,N)
    data = I+";"+str(A)

    url = "http://127.0.0.1:5000/1?data="+data
    r = requests.get(url, headers={'Connection': 'close'})
    data = r.text.encode('ascii').split(';')
    salt = int(data[0])
    B = int(data[1])
    
    uH = sha256(hex(A+B)[2:].replace('L','')).hexdigest()
    u = int(uH,16)
    
    xH = sha256(hex(salt)[2:]+P).hexdigest()
    x = int(xH,16)

    temp = pow(g,x,N)
    S = pow(B-(k*temp),a+(u*x),N)

    K = sha256(hex(S)[2:].replace('L','')).hexdigest()
    hmac = HMAC_SHA256(K,hex(D['salt'])[2:])

    url = "http://127.0.0.1:5000/2?data="+hmac
    r = requests.get(url, headers={'Connection': 'close'})
    print r.text


################################################################################
###### 
################################################################################

def random_str(start,stop):
    size = randint(start,stop)
    output = ""
    for i in range(size):
        output+=chr(randint(1,255))
    return output

def random_aes_key(x):
    return random_str(x,x)

def xor(a,b):
    raw_a = a
    raw_b = b
    return "".join([chr(ord(raw_a[i])^ord(raw_b[i])) for i in range(len(raw_a))])


def HMAC_SHA256(data,k,blocksize=64):
    if len(k) > blocksize:
        k = sha256(k).hexdigest().decode("hex")

    if len(k) < blocksize:
        k = k + "\x00"*(blocksize-len(k))
    
    o_key_pad = xor(k,"\x5c"*blocksize)
    i_key_pad = xor(k,"\x36"*blocksize)

    h = sha256(o_key_pad + sha256(i_key_pad + data).hexdigest().decode("hex")).hexdigest()
    return h


def init_server():
    global D
    D = {}
    salt = randint(0,0xFFFFFFFF)
    xH = sha256(hex(salt)[2:]+P).hexdigest()

    x = int(xH,16)
    v = pow(g,x,N)
    D['salt'] = salt
    D['v'] = v

    #Starting the server
    x = threading.Thread(target=app.run)
    x.setDaemon(True)
    x.start()    
    return x

from flask import Flask,request,abort
import threading
import logging

global app
app = Flask(__name__)
app.jinja_env.cache = {} #I don't think it helps, but if it's on the Internet it's true, right?!
log = logging.getLogger('werkzeug')
log.disabled = True

@app.route('/register', methods=['GET'])
def register():
    global D
    username = request.args.get('username').encode('ascii')
    password = request.args.get('password').encode('ascii')

    D[username] = {}

    salt = randint(0,0xFFFFFFFF)
    xH = sha256(hex(salt)[2:]+password).hexdigest()

    x = int(xH,16)
    v = pow(g,x,N)

    D[username]['salt'] = salt
    D[username]['v'] = v

    return "Nice!!! User %s has been registered" %(username)


@app.route('/1', methods=['GET'])
def first():
    data = request.args.get('data').encode('ascii').split(';')
    client_I = data[0]
    A = int(data[1])

    b = randint(0,N)
    server_B = k*D['v'] + pow(g,b,N)
    D['A'] = A
    D['b'] = b
    D['B'] = server_B
    return str(D['salt'])+';'+str(server_B)

@app.route('/2', methods=['GET'])
def second():
    global D
    data = request.args.get('data').encode('ascii')
    client_hmac = data

    server_uH = sha256(hex(D['A']+D['B'])[2:].replace('L','')).hexdigest()
    u = int(server_uH,16)

    temp = pow(D['v'],u,N)
    S = pow(D['A']*temp,D['b'],N)

    K = sha256(hex(S)[2:].replace('L','')).hexdigest()
    server_hmac = HMAC_SHA256(K,hex(D['salt'])[2:])

    if server_hmac == client_hmac:
        return 'OK'
    return 'FAIL'
    
    sys.exit()

main()
