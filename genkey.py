#!/usr/bin/python
# -*- coding: latin-1 -*-

import hashlib
import binascii
import optparse
import sys
from prng import Prng, PrngV1, PrngV2
import getpass

version="v0.4.0"
        
def genKeyV1(label,seed=None):
    saltedSeed = ""
    if seed:
        saltedSeed += seed
    saltedSeed += label
    saltedSeed += "RI31DsbekAeVPP27DqyxkhyuoJsxhRZQ5UhKhellEshxZjZ8ADWol2R3GFMMbkBu"
    m = hashlib.sha512()
    m.update(saltedSeed)
    result = m.digest()
    return binascii.unhexlify(binascii.hexlify(result)[7:7+64])

def genKeyV2(label,seed=None):
    prng = PrngV1(deterministic=True, constantEntropy=seed)
    prng.addEntropy(label)
    prng.skip(655360)
    prng.addEntropy(label)
    prng.skip(655360)
    result = prng.getRandomBytes(32)
    return result

def genKeyV3(label,seed=None):
    prng = PrngV2(deterministic=True, seed=seed)
    prng.addEntropy(label)
    prng.skip(64*100000)
    return prng.getRandomBytes(32)

genKeyMap = {
    1: genKeyV1,
    2: genKeyV2,
    3: genKeyV3,
}

if __name__ == "__main__":
    
    parser = optparse.OptionParser()

    parser.add_option("-v", "--version",
                      action="store", dest="version", type="int", default=2,
                      help="Random seed")

    (options, args) = parser.parse_args()

    version = options.version

    seed = getpass.getpass("seed:")

    try:
        genKey = genKeyMap[version]
    except:
        print "unkown version: %d" % options.version
        sys.exit(1)

    while(True):

        label = getpass.getpass("label:")

        if label == "":
            sys.exit(0)

        key = genKey(label, seed)

        print "genkey-v%d: %+20s : %s" % (options.version, label, binascii.hexlify(key))

        
