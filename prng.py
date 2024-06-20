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

import bip39words
from hmac_drbg import HmacDrbg

version = "v3.1.0"

# pwcharset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
pwcharset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
unique_id_charset = "abcdefghijklmnopqrstuvwxyz"
pwdigitset = "0123456789"

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
        if not self.deterministic:
            self.addExternalEntropy()

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

    def get_random_integer(self, max_value):
        pow2 = 1
        nbits = 0
        while pow2 < max_value:
            pow2 *= 256
            nbits += 8
        while True:
            value = self.getRandomLong(nbits)
            if value < max_value:
                return value

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


def split_value(value, item_count, item_range):
    work_value = value
    result = []
    entropy = 1
    for i in range(item_count):
        result.append(work_value % item_range)
        entropy *= item_range
        work_value //= item_range
        if work_value <= item_range:
            raise OverflowError
    bits_entropy = 0
    while entropy > 1:
        entropy //= 2
        bits_entropy += 1
    return (result, bits_entropy)


def long2str(value, charset, length):
    (arr, entropy) = split_value(value, length, len(charset))
    result = ""
    for index in arr:
        result += charset[index]
    return f"{result} ({entropy} bits)"


def get_words_password(value, nwords=4, uppercase=False, sep=' ', digits=False):
    dico = open("mots_francais.txt").read().split("\n")
    (arr, entropy) = split_value(value, nwords, len(dico))
    result = []
    count = 1
    for index in arr:
        prefix = ""
        if digits:
            prefix += f"{count}"
            count += 1
        mot = dico[index]
        if uppercase:
            mot = mot[0].upper() + mot[1:]
        result.append(prefix + mot)
    return f"{sep.join(result)} ({entropy} bits)"

# def show_password(prompt, value, charset):


def genRandomInteractive(prng, lang="english"):
    result = prng.random_bytes(size=64)
    long_result = bytes2long(result)
    hexResult = binascii.hexlify(result)

    offset = 0

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
    print("Unique key (6 chars)  : %s" % long2str(long_result, unique_id_charset, 6))
    print("")
    print("Password (16 chars)  : %s" % long2str(long_result, pwcharset, 16))
    print("Password (24 chars)  : %s" % long2str(long_result, pwcharset, 24))
    print("Password (32 chars)  : %s" % long2str(long_result, pwcharset, 32))
    print("Password (48 chars)  : %s" % long2str(long_result, pwcharset, 48))
    print("")
    print("Pincode (4 digits)  : %s" % long2str(long_result, pwdigitset, 4))
    print("Pincode (6 digits)  : %s" % long2str(long_result, pwdigitset, 6))
    print("Pincode (8 digits)  : %s" % long2str(long_result, pwdigitset, 8))
    # print("Password (16 digits) : %s" % long2str(long_result, "0123456789", 16))
    # print("Password (32 digits) : %s" % long2str(long_result, "0123456789", 32))
    print("")
    print("Password (4 words)  : %s" % get_words_password(long_result))
    print("Password (5 words)  : %s" % get_words_password(long_result, nwords=5))
    print("Password (6 words)  : %s" % get_words_password(long_result, nwords=6))
    # print("Password (4 words)  : %s" % get_words_password(long_result, sep=";", uppercase=True, digits=True))
    print("")
    print("BIP39 12 words: " + " ".join(bip39Seed12))
    print("BIP39 24 words: " + " ".join(bip39Seed24))
    print("--------------------------------------------------------------------------------")


# ref: https://proton.me/blog/what-is-password-entropy


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
        prng.addExternalEntropy()
        prng.add_entropy(genKey(userdata, prng.impl.random_bytes(32)))
        genRandomInteractive(prng, options.lang)

    # """
    # data = getRandomData(256*1024*1024)
    # f = open("random1.dat","w")
    # f.write(data)
    # f.close()
    # """
