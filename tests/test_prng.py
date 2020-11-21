#!/usr/bin/env python3

import unittest
from prng import Prng


class Test_Prng(unittest.TestCase):

    def test_deterministic_Prng_2_1(self):
        prng = Prng(deterministic=True)
        value = prng.getRandomLong(32)
        expected = 3563776190
        self.assertEqual(value, expected, "Prng not deterministic (expected: %d, got: %d)" % (expected, value))

    def test_deterministic_Prng_2_2(self):
        prng = Prng(deterministic=True)
        prng.addEntropy(b"entropy")
        value = prng.getRandomLong(32)
        expected = 1783747816
        self.assertEqual(value, expected, "Prng not deterministic (expected: %d, got: %d)" % (expected, value))


if __name__ == '__main__':
    unittest.main()
