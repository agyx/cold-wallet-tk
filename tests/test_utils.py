#!/usr/bin/env python3

import unittest
import utils
import binascii

"""
class Test_Utils(unittest.TestCase):

    def test_passwordFromLong_1(self):
        pw = utils.passwordFromLong(2797116790942351069039053030881080973412)
        expected = "22MUVhgDXWAnvcSgxBoHWY"
        self.assertEquals(pw, expected, "wrong password: %s (expected: %s)" % (pw, expected))

    def test_longFromPassword_1(self):
        value = utils.longFromPassword("22MUVhgDXWAnvcSgxBoHWY")
        expected = 2797116790942351069039053030881080973412
        self.assertEquals(value, expected, "wrong value: %d (expected: %d)" % (value, expected))
"""


if __name__ == '__main__':
    unittest.main()
