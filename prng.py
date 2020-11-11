#!/usr/bin/env python
# -*- coding: latin-1 -*-

import hashlib
import hmac
import getpass
import binascii
import time
import os
import random
from numpy import log2
from StringIO import StringIO
import bip39
import optparse

version="v2.1.0"

pwcharset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

class PrngV2:
    """
    if deterministic, HMAC_DRBG (SHA-512) as specified in NIST SP 800-90A.
    http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf
    Proof that HMAC_DRBG has not backdoor:
    https://www.schneier.com/blog/archives/2017/08/proof_that_hmac.html
    """
    def __init__(self, deterministic=False, seed=""):
        self.deterministic = deterministic
        self.key = b'\x00' * 64
        self.val = b'\x01' * 64
        self.reseed(seed)
        self.stream = StringIO()
        self.streamlen = 0
        self.round = 0
        self.timestampRef = 0

    def addEntropy(self, entropy):
        self.reseed(entropy)

    def hmac(self, key, val):
        return hmac.new(key, val, hashlib.sha512).digest()

    def reseed(self, data=b''):
        self.key = self.hmac(self.key, self.val + b'\x00' + data)
        self.val = self.hmac(self.key, self.val)

        if data:
            self.key = self.hmac(self.key, self.val + b'\x01' + data)
            self.val = self.hmac(self.key, self.val)

    def produceRandomData(self):
        if not self.deterministic:
            self.addExternalEntropy()
        self.val = self.hmac(self.key, self.val)
        self.stream.write(self.val)
        self.streamlen += len(self.val)
        self.round += 1

    def addExternalEntropy(self):
        self.addEntropy(os.urandom(64))
        now = time.time()
        self.addEntropy("%.20f" % now)
        delta = now - self.timestampRef
        self.timestampRef = now
        self.addEntropy("%.20f" % delta)
        self.addEntropy("%d" % os.getpid())
        self.addEntropy("%d" % os.getppid())

    def skip(self, nBytes):
        if nBytes <= self.streamlen:
            self.getRandomBytes(nBytes)
        else:
            leftToSkipped = nBytes
            buflen = 1000000
            while leftToSkipped > buflen:
                self.getRandomBytes(buflen)
                leftToSkipped -= buflen
            self.getRandomBytes(leftToSkipped)

    def getRandomBytes(self, length):
        while self.streamlen < length:
            self.produceRandomData()
        streamstr = self.stream.getvalue()
        # print("len(streamstr): {:d}".format(len(streamstr)))
        # print("self.streamlen: {:d}".format(self.streamlen))
        result = streamstr[:length]

        # we discard the remainder of the buffer because
        # for unknown reasons, the init string of StringIO()
        # is sometimes discarded

        # new_stream_string = streamstr[length:]
        # self.streamlen = len(new_stream_string)
        self.stream = StringIO()
        self.streamlen = 0

        return result

    def getRandomLong(self, nBits):
        if nBits % 8 != 0:
            raise ValueError("argument should be a multiple of 8: %d" % nBits)
        nBytes = nBits / 8
        rnTable = self.getRandomBytes(nBytes)
        result = 0L
        if nBytes >= 1:
            for i in range(nBytes):
                result = (result << 8) + ord(rnTable[i])
        return result


class PrngV1:
    
    def __init__(self, deterministic=False, seed="", constantEntropy=None):
        self.deterministic = deterministic
        self.constantEntropy = constantEntropy
        self.timestampRef = 0
        self.seed = "fOWxgguwXIBK7Dzojk8Pb4T9sJFfPf2rnNurmEO1hOZqxnVvknBxxnjir9v9drSG"+seed
        self.seed += self.currentTimeString()
        self.stream = StringIO()
        self.streamlen = 0
        self.round = 0

    def currentTimeString(self):
        if self.deterministic:
            return ""
        return "%.20f" % time.time()

    def currentTimeDeltaString(self):
        if self.deterministic:
            return ""
        delta = time.time() - self.timestampRef
        self.timestampRef = time.time()
        return "%.20f" % delta
        
    def addEntropy(self, entropy):
        self.seed += entropy

    def produceRandomData(self):
        self.seed += self.currentTimeString()
        self.seed += self.currentTimeDeltaString()
        if not self.deterministic:
            self.seed += os.urandom(32)
        self.seed += "p3PLfM9hHHmhYws1RYVv6jmzZcGTAaTIQCbMidU6qh3aXQmLm0hJEODSNNwgQTJm"
        self.seed += str(self.round)
        if self.constantEntropy:
            self.seed += self.constantEntropy

        m = hashlib.sha512()
        m.update(self.seed)
        self.seed = m.digest()
        
        m = hashlib.sha512()
        m.update(self.seed)
        self.seed = m.digest()

        if not self.deterministic:
            charlist = list(self.seed)
            random.shuffle(charlist)
            self.seed = "".join(charlist)
        
        self.stream.write(self.seed)
        self.streamlen += len(self.seed)
        self.round += 1

    def skip(self, nBytes):
        if nBytes <= self.streamlen:
            self.getRandomBytes(nBytes)
        else:
            leftToSkipped = nBytes
            buflen = 1000000
            while leftToSkipped > buflen:
                self.getRandomBytes(buflen)
                leftToSkipped -= buflen
            self.getRandomBytes(leftToSkipped)

    def getRandomBytes(self, length):
        while self.streamlen < length:
            self.produceRandomData()
        streamstr = self.stream.getvalue()
        result = streamstr[:length]
        self.stream = StringIO(streamstr[length:])
        self.streamlen = self.streamlen - length
        return result    
 
    def getRandomLong(self, nBits):
        if nBits % 8 != 0:
            raise ValueError("argument should be a multiple of 8: %d" % nBits)
        nBytes = nBits/8
        rnTable = self.getRandomBytes(nBytes)
        result = 0L
        if nBytes >= 1:
            for i in range(nBytes):
                result = (result << 8) + ord(rnTable[i])
        return result
    
class Prng(PrngV2):
    pass

    
def genRandomInteractive(prng, lang="english"):
    result = prng.getRandomBytes(length = 64)
    hexResult = binascii.hexlify(result)

    offset = 0

    def mapPasswordChar(char):
        return pwcharset[ord(char) % len(pwcharset)]

    seed128bits = hexResult[offset:offset+32]
    seed256bits = hexResult[offset:offset+64]
    
    bip39Seed12 = bip39.BIP39FromHex(seed128bits, lang)
    bip39Seed24 = bip39.BIP39FromHex(seed256bits, lang)
    
    print("--------------------------------------------------------------------------------")
    print("round #%d" % prng.round)
    print("128 bits: " + seed128bits)
    #print "192 bits: " + hexResult[offset:offset+48]
    print("256 bits: " + seed256bits)
    #print "512 bits: " + hexResult[offset:offset+128]
    print("")
    print("Password (16 chars, %3d bits entropy): %s" % (int(log2(len(pwcharset))*16), "".join(map(mapPasswordChar, result[:16]))))
    print("Password (24 chars, %3d bits entropy): %s" % (int(log2(len(pwcharset))*24), "".join(map(mapPasswordChar, result[:24]))))
    print("Password (32 chars, %3d bits entropy): %s" % (int(log2(len(pwcharset))*32), "".join(map(mapPasswordChar, result[:32]))))
    print("Password (48 chars, %3d bits entropy): %s" % (int(log2(len(pwcharset))*48), "".join(map(mapPasswordChar, result[:48]))))
    #print "Password (64 chars, %3d bits entropy): %s" % (int(log2(len(pwcharset))*64), password64)
    print("")
    print("BIP39 12 words: " + " ".join(bip39Seed12))
    print("BIP39 24 words: " + " ".join(bip39Seed24))
    print("--------------------------------------------------------------------------------")

if __name__ == "__main__": 

    parser = optparse.OptionParser()

    parser.add_option("-l", "--lang",
                      action="store", dest="lang", default="english", type="str",
                      help="Language used for BIP39 mnemonic")

    (options, args) = parser.parse_args()

    prng = Prng()

    while True:
        from genkey import genKeyV3
        userdata = getpass.getpass("What's up today? :")
        prng.addEntropy(genKeyV3(userdata,prng.getRandomBytes(32)))
        genRandomInteractive(prng, options.lang)
        
    #"""
    #data = getRandomData(256*1024*1024)
    #f = open("random1.dat","w")
    #f.write(data)
    #f.close()
    #"""

