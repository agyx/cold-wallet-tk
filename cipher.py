#!/usr/bin/python
# -*- coding: latin-1 -*-

import hashlib
import optparse
import sys
from prng import Prng
import getpass
import utils
from StringIO import StringIO
import genkey
import hmac

version = "v0.3.1"

def cipher(message, key):
    prng = Prng(deterministic=True, seed=key)
    randomString = prng.getRandomBytes(len(message))
    stream = StringIO()
    for i in range(len(message)):
        stream.write(chr(ord(message[i])^ord(randomString[i])))
    return stream.getvalue()

MAGIC = "CWCI"
VERSION = 3

def authenticate(data, key):
    sha = hashlib.sha256()
    sha.update(data)
    return hmac.new(key, sha.digest(), hashlib.sha256).digest()

def encrypt(plaintext, password):
    nonce = Prng().getRandomBytes(32)
    key = genkey.genKeyV3(password, nonce)
    ciphertext = cipher(plaintext, key)
    return MAGIC + utils.rawFromLong(VERSION, 16) + nonce + authenticate(ciphertext, key) + ciphertext

def decrypt(cipherfile, password):
    if cipherfile[0:4] != MAGIC:
        raise Exception("bad magic")
    readVersion = utils.longFromRaw(cipherfile[4:6])
    if readVersion != VERSION:
        raise Exception("unknown version: %d" % readVersion)
    nonce = cipherfile[6:38]
    key = genkey.genKeyV3(password, nonce)
    readMac = cipherfile[38:70]
    ciphertext = cipherfile[70:]
    mac = authenticate(ciphertext, key)
    if readMac != mac:
        raise Exception("bad authentication tag")
    plaintext = cipher(ciphertext, key)
    return plaintext

if __name__ == "__main__":

    parser = optparse.OptionParser()

    parser.add_option("-e", "--encrypt",
                      action="store", dest="filenameToEncrypt", default=None,
                      help="Input file to be encrypted")

    parser.add_option("-d", "--decrypt",
                      action="store", dest="filenameToDecrypt", default=None,
                      help="Input file to be decrypted")

    (options, args) = parser.parse_args()

    if options.filenameToEncrypt and options.filenameToDecrypt:
        print "cannot encrypt and decrypt at the same time"
        sys.exit(1)

    if not options.filenameToEncrypt and not options.filenameToDecrypt:
        print "please provide a function to perform"
        sys.exit(1)

    password = getpass.getpass("password:")

    if options.filenameToEncrypt:

        f = open(options.filenameToEncrypt,"r")
        plaintext = f.read()
        f.close()

        f = open(options.filenameToEncrypt+".encrypted","w")
        f.write(encrypt(plaintext, password))
        f.close()

        print "File successfully encrypted"

    elif options.filenameToDecrypt:

        f = open(options.filenameToDecrypt,"r")
        cipherfile = f.read()
        f.close()

        try:
            plaintext = decrypt(cipherfile, password)
            f = open(options.filenameToDecrypt + ".decrypted", "w")
            f.write(plaintext)
            f.close()
            print "File successfully decrypted"
        except Exception as e:
            print e.message


