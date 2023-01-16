#!/usr/bin/env python3
# -*- coding: latin-1 -*-

import hashlib
import hmac
import getpass
import binascii
import time
import os
import random
from io import BytesIO
import bip39
import optparse

version = "v3.0.0"

pwcharset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


class Prng:
    """
    if deterministic, HMAC_DRBG (SHA-512) as specified in NIST SP 800-90A.
    http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf
    Proof that HMAC_DRBG has not backdoor:
    https://www.schneier.com/blog/archives/2017/08/proof_that_hmac.html
    """

    def __init__(self, deterministic=False, seed=b""):
        self.deterministic = deterministic
        self.key = b'\x00' * 64
        self.val = b'\x01' * 64
        self.reseed(seed)
        self.stream = BytesIO()
        self.streamlen = 0
        self.round = 0
        self.timestampRef = 0

    def addEntropy(self, entropy):
        self.reseed(entropy)

    def hmac(self, key, val):
        return hmac.new(key, val, hashlib.sha512).digest()

    def reseed(self, data=b""):
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
        self.addEntropy(("%.20f" % now).encode("utf-8"))
        delta = now - self.timestampRef
        self.timestampRef = now
        self.addEntropy(("%.20f" % delta).encode("utf-8"))
        self.addEntropy(("%d" % os.getpid()).encode("utf-8"))
        self.addEntropy(("%d" % os.getppid()).encode("utf-8"))

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
        self.stream = BytesIO()
        self.streamlen = 0

        return result

    def getRandomLong(self, nBits):
        if nBits % 8 != 0:
            raise ValueError("argument should be a multiple of 8: %d" % nBits)
        nBytes = nBits // 8
        rnTable = self.getRandomBytes(nBytes)
        result = 0
        if nBytes >= 1:
            for i in range(nBytes):
                result = (result << 8) + rnTable[i]
        return result


def bytes2long(_bytes):
    result = 0
    for byte in _bytes:
        result <<= 8
        result |= byte
    return result


def long2str(value, mapfn, modulo, length):
    work_value = value
    result = ""
    for _ in range(length):
        result += mapfn(work_value % modulo)
        work_value //= modulo
        if work_value <= modulo:
            raise OverflowError
    return result


def genRandomInteractive(prng, lang="english"):
    result = prng.getRandomBytes(length=64)
    long_result = bytes2long(result)
    hexResult = binascii.hexlify(result)

    offset = 0

    def mapPasswordChar(char):
        return pwcharset[char % len(pwcharset)]

    def mapPasswordDigit(char):
        return chr(ord('0') + char % 10)

    seed128bits = hexResult[offset:offset + 32]
    seed256bits = hexResult[offset:offset + 64]

    bip39Seed12 = bip39.BIP39FromHex(seed128bits, lang)
    bip39Seed24 = bip39.BIP39FromHex(seed256bits, lang)

    print("--------------------------------------------------------------------------------")
    print("round #%d" % prng.round)
    print("128 bits: " + seed128bits.decode("utf-8"))
    # print "192 bits: " + hexResult[offset:offset+48]
    print("256 bits: " + seed256bits.decode("utf-8"))
    # print "512 bits: " + hexResult[offset:offset+128]
    print("")
    print("Password (16 chars)  : %s" % long2str(long_result, mapPasswordChar, len(pwcharset), 16))
    print("Password (24 chars)  : %s" % long2str(long_result, mapPasswordChar, len(pwcharset), 24))
    print("Password (32 chars)  : %s" % long2str(long_result, mapPasswordChar, len(pwcharset), 32))
    print("Password (48 chars)  : %s" % long2str(long_result, mapPasswordChar, len(pwcharset), 48))
    print("Password (4 digits)  : %s" % long2str(long_result, mapPasswordDigit, 10, 4))
    print("Password (8 digits)  : %s" % long2str(long_result, mapPasswordDigit, 10, 8))
    print("Password (16 digits) : %s" % long2str(long_result, mapPasswordDigit, 10, 16))
    print("Password (32 digits) : %s" % long2str(long_result, mapPasswordDigit, 10, 32))
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
        from genkey import genKey

        userdata = getpass.getpass("What's up today? :")
        prng.addEntropy(genKey(userdata, prng.getRandomBytes(32)))
        genRandomInteractive(prng, options.lang)

    # """
    # data = getRandomData(256*1024*1024)
    # f = open("random1.dat","w")
    # f.write(data)
    # f.close()
    # """
