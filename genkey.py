#!/usr/bin/env python3
# -*- coding: latin-1 -*-

import hashlib
import binascii
import optparse
import sys
from prng import Prng
import getpass

version = "v0.4.0"


def genKey(label, seed=None):
    prng = Prng(deterministic=True, seed=seed)
    prng.add_entropy(label.encode("utf-8"))
    prng.skip(64 * 100000)
    return prng.random_bytes(32)


if __name__ == "__main__":

    seed = getpass.getpass("seed:")

    while True:

        label = getpass.getpass("label:")

        if label == "":
            sys.exit(0)

        key = genKey(label, seed)

        print("genkey-v%d: %+20s : %s" % (options.version, label, binascii.hexlify(key)))
