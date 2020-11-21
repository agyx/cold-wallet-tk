#!/usr/bin/env python3

import unittest
import genkey
import binascii


class Test_GenKey(unittest.TestCase):

    def test_genKey_1(self):
        hex = binascii.hexlify(genkey.genKey("a", b"b"))
        self.assertEqual(hex, b"47cf12fe6d38c12d154f880d3e1466c966ac874a3f24db73e942eb8c57e42610", "wrong genkey")


if __name__ == '__main__':
    unittest.main()
