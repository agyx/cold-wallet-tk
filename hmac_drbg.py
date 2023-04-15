#!/usr/bin/env python3

import hashlib
import hmac
from io import BytesIO

version = "v1.0.0"


class HmacDrbg:
    """
    HMAC_DRBG (SHA-512) as specified in NIST SP 800-90A.
    http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf
    Proof that HMAC_DRBG has not backdoor:
    https://www.schneier.com/blog/archives/2017/08/proof_that_hmac.html
    """

    def __init__(self, seed=b""):
        self.key = b'\x00' * 64
        self.val = b'\x01' * 64
        self.add_entropy(seed)

    def hmac(self, val):
        return hmac.new(self.key, val, hashlib.sha512).digest()

    def add_entropy(self, data=b""):
        self.key = self.hmac(self.val + b'\x00' + data)
        self.val = self.hmac(self.val)
        if data:
            self.key = self.hmac(self.val + b'\x01' + data)
            self.val = self.hmac(self.val)

    def random_bytes(self, length):
        stream = BytesIO()
        streamlen = 0
        while streamlen < length:
            self.val = self.hmac(self.val)
            stream.write(self.val)
            streamlen += len(self.val)
        return stream.getvalue()[:length]


# if __name__ == "__main__":
#     prng = HmacDrbg()
