#!/usr/bin/env python3
# coding=utf-8

from prng import Prng
import optparse
import binascii
import getpass
import bip39
from utils import *

version = "v0.2.2"

# https://primes.utm.edu/lists/2small/
# https://www.numberempire.com/primenumbers.php
widthSets = [
    (32, 2 ** 32 - 5),
    (64, 2 ** 64 - 59),
    (96, 2 ** 96 - 17),
    (128, 2 ** 128 - 159),
    (160, 2 ** 160 - 47),
    (192, 2 ** 192 - 237),
    (224, 2 ** 224 - 63),
    (256, 2 ** 256 - 189),
    (384, 2 ** 256 - 317),
    (512, 2 ** 512 - 569),
]


class Shamir:

    def __init__(self, k, n, width):
        self.k = k
        self.n = n
        self.width = width
        self.P = 0

        for widthSet in widthSets:
            if widthSet[0] == width:
                self.P = widthSet[1]
                break

        if self.P == 0:
            raise ValueError("incorrect width: %d" % width)

    @staticmethod
    def fPoly(x, poly, prime):
        result = 0
        for i in range(len(poly)):
            result += poly[i] * x ** i
        return result % prime

    @staticmethod
    def bezout(a, b):
        """ Calcule (u, v, p) tels que a*u + b*v = p et p = pgcd(a, b) """
        if a == 0 and b == 0:
            return 0, 0, 0
        if b == 0:
            return a // abs(a), 0, abs(a)
        (u, v, p) = Shamir.bezout(b, a % b)
        return v, (u - v * (a // b)), p

    @staticmethod
    def inv(x, m):
        """ Calcule y dans [[0, m-1]] tel que x*y % m == 1 """
        return Shamir.bezout(x, m)[0] % m

    def split(self, secret):

        if secret >= self.P:
            raise ValueError("secret must be smaller than P")

        prng = Prng(deterministic=True)
        prng.addEntropy(secret.to_bytes(512, byteorder="big"))

        a = [0] * self.k

        a[0] = secret

        for i in range(1, self.k):
            a[i] = prng.getRandomLong(512) % self.P

        x = []

        for i in range(self.n):
            while True:
                r = int(prng.getRandomLong(16))
                if r != 0 and r not in x:
                    x += [r]
                    break

        y = [0] * self.n

        for i in range(self.n):
            y[i] = Shamir.fPoly(x[i], a, self.P)

        shares = []

        for i in range(self.n):
            shares += [(x[i], y[i])]

        return shares

    def combine(self, shares):

        sx = [0] * self.k
        sy = [0] * self.k
        secret = 0

        for i in range(self.k):
            sx[i] = shares[i][0]
            sy[i] = shares[i][1]

        for i in range(self.k):
            num = 1
            den = 1
            for j in range(self.k):
                if i != j:
                    num *= sx[j]
                    den *= sx[j] - sx[i]
            secret += sy[i] * num * Shamir.inv(den, self.P)

        return secret % self.P


class ShareProtocolV1(object):
    def __init__(self, k=None, width=None, share=None):
        self.version = 1

        if share:
            (shareVersion, k, _, _) = self.decodeAll(share)

            if shareVersion != self.version:
                raise ValueError("unknown share version: %d" % shareVersion)

            self.k = k
            self.width = len(share) * 8 - 32
        else:
            self.k = k
            self.width = width

    def encode(self, share):
        prng = Prng(deterministic=True)
        prng.addEntropy(share[0].to_bytes(512, byteorder="big") + share[1].to_bytes(512, byteorder="big"))
        result = b""
        result += bytes([prng.getRandomLong(8) & 0xF0 | self.version])
        result += bytes([prng.getRandomLong(8) & 0xF0 | self.k])
        result += rawFromLong(share[0], 16)
        result += rawFromLong(share[1], self.width)
        return result

    def decodeAll(self, share):
        version = share[0] & 0x0F
        k = share[1] & 0x0F
        x = longFromRaw(share[2:4])
        y = longFromRaw(share[4:])
        return version, k, x, y

    def decode(self, share):
        (version, k, x, y) = self.decodeAll(share)
        if version != self.version:
            raise Exception("incompatible version in share: %d" % version)
        if k != self.k:
            raise Exception("incompatible k in share: %d" % k)
        return (x, y)


def cliSplit(k, n, secret, lang):
    formatBIP39 = False

    while True:
        try:
            raw = binascii.unhexlify(secret)
            break
        except Exception:
            pass
        try:
            raw = bip39.rawFromBIP39(secret.split())
            formatBIP39 = True
        except Exception:
            raw = b"SHTF" + (len(secret)).to_bytes(1, byteorder="big") + secret.encode("utf-8")
            len_stuff = 512 // 8 - len(raw)
            raw += b" " * len_stuff
        break

    shamir = Shamir(k=k, n=n, width=len(raw) * 8)

    shares = shamir.split(longFromRaw(raw))

    protocol = ShareProtocolV1(k=shamir.k, width=shamir.width)

    encodedShares = map(protocol.encode, shares)

    if formatBIP39:
        formatedShares = [" ".join(bip39.BIP39FromRaw(x, lang=lang)) for x in encodedShares]
    else:
        formatedShares = [binascii.hexlify(x).decode("utf-8") for x in encodedShares]

    #formatedShares = [x.encode("utf-8") for x in formatedShares]

    return formatedShares


def cliShareGenerator():
    index = 1
    while True:
        yield getpass.getpass("Share %d (hex or BIP39):" % index)
        index += 1


def cliCombine(shareGenerator, lang):
    protocol = None
    shares = []

    for share in shareGenerator():

        try:
            raw = binascii.unhexlify(share)
            formatBIP39 = False
        except:
            raw = bip39.rawFromBIP39(share.split())
            formatBIP39 = True

        if not protocol:
            protocol = ShareProtocolV1(share=raw)

        shares += [protocol.decode(raw)]

        if protocol.k == len(shares):
            break

    shamir = Shamir(k=protocol.k, n=0, width=protocol.width)

    secret = shamir.combine(shares)

    if formatBIP39:
        formattedSecret = " ".join(bip39.BIP39FromLong(secret, width=protocol.width, lang=lang))
    else:
        raw = rawFromLong(secret, width=protocol.width)
        if raw.startswith(b"SHTF"):
            len_text = raw[4]
            formattedSecret = (raw[5:5 + len_text]).decode("utf-8")
        else:
            formattedSecret = binascii.hexlify(raw).decode("utf-8")

    return formattedSecret


def autotest(k, shares, expected):
    n = len(shares)
    counter = [0] * k
    while True:
        duplicate = False
        for i in range(k):
            for j in range(k):
                if i == j:
                    continue
                if counter[i] == counter[j]:
                    duplicate = True
                    break
            if duplicate:
                break
        if not duplicate:
            # print("testing {}".format(counter))
            # selected_shares = [shares[counter[i]] for i in range(k)])

            def gen_shares():
                for i in range(k):
                    yield shares[counter[i]]

            found = cliCombine(gen_shares, lang="english")
            if found != expected:
                print("error: found '{}' selected_shares indices: {}".format(found, counter))
                exit(1)
        shall_exit = True
        for i in range(k):
            counter[i] += 1
            if counter[i] == n:
                counter[i] = 0
            else:
                shall_exit = False
                break
        if shall_exit:
            break


if __name__ == "__main__":

    parser = optparse.OptionParser()

    parser.add_option("-k", "",
                      action="store", dest="k", default=None, type="int",
                      help="Number of shares necessary to retrieve the secret")

    parser.add_option("-n", "",
                      action="store", dest="n", default=None, type="int",
                      help="Number of shares to be produced")

    parser.add_option("-s", "--split",
                      action="store_true", dest="split", default=False,
                      help="Split a secret into shares")

    parser.add_option("-c", "--combine",
                      action="store_true", dest="combine", default=False,
                      help="Combine shares into the secret")

    parser.add_option("-l", "--lang",
                      action="store", dest="lang", default="english", type="str",
                      help="Language used for BIP39 mnemonic")

    (options, args) = parser.parse_args()

    if options.split:

        if not options.k:
            raise ValueError("need k parameter")

        if not options.n:
            raise ValueError("need n parameter")

        if options.combine:
            raise Exception("cannot split and combine at the same time")

        secret = getpass.getpass("Secret (text, hex or BIP39):")

        shares = cliSplit(options.k, options.n, secret, options.lang)

        autotest(options.k, shares, secret)

        for i in range(len(shares)):
            print("share %d: %s" % (i + 1, shares[i]))

    elif options.combine:

        if options.split:
            raise Exception("cannot split and combine at the same time")

        if options.k:
            raise Exception("parameter k not required")

        if options.n:
            raise Exception("parameter n not required")

        print("secret: %s" % cliCombine(cliShareGenerator, options.lang))
