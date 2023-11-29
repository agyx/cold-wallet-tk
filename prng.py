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

from hmac_drbg import HmacDrbg

version = "v3.1.0"

# pwcharset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
pwcharset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"


class Prng:
    """
    if deterministic, HMAC_DRBG (SHA-512) as specified in NIST SP 800-90A.
    http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf
    Proof that HMAC_DRBG has not backdoor:
    https://www.schneier.com/blog/archives/2017/08/proof_that_hmac.html
    """

    def __init__(self, deterministic=False, seed=b""):
        self.deterministic = deterministic
        self.round = 0
        self.timestampRef = 0
        self.impl = HmacDrbg(seed=seed)

    def addExternalEntropy(self):
        self.add_entropy(os.urandom(64))
        now = time.time()
        self.add_entropy(("%.20f" % now).encode("utf-8"))
        delta = now - self.timestampRef
        self.timestampRef = now
        self.add_entropy(("%.20f" % delta).encode("utf-8"))
        self.add_entropy(("%d" % os.getpid()).encode("utf-8"))
        self.add_entropy(("%d" % os.getppid()).encode("utf-8"))

    def skip(self, nBytes):
        self.random_bytes(nBytes)

    def add_entropy(self, entropy):
        self.impl.add_entropy(entropy)

    def getRandomLong(self, nBits):
        if nBits % 8 != 0:
            raise ValueError("argument should be a multiple of 8: %d" % nBits)
        nBytes = nBits // 8
        rnTable = self.random_bytes(nBytes)
        result = 0
        if nBytes >= 1:
            for i in range(nBytes):
                result = (result << 8) + rnTable[i]
        return result

    def random_bytes(self, size):
        self.round += 1
        return self.impl.random_bytes(size)


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
    result = prng.random_bytes(size=64)
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
        prng.add_entropy(genKey(userdata, prng.impl.random_bytes(32)))
        genRandomInteractive(prng, options.lang)

    # """
    # data = getRandomData(256*1024*1024)
    # f = open("random1.dat","w")
    # f.write(data)
    # f.close()
    # """
