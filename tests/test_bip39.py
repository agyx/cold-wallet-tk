#!/usr/bin/env python3

import unittest
import bip39


class Test_BIP39(unittest.TestCase):

    def test_bip39_decode_1(self):
        hex = bip39.hexFromBIP39(
            "model sword civil lunar sustain wasp practice search cloth blame oppose music".split())
        self.assertEqual(hex, "8e9b88a6428dafef2a5e102bc2e66e48", "wrong decoding of mnemonic")

    def test_bip39_encode_1(self):
        mnemonic = bip39.BIP39FromHex("8e9b88a6428dafef2a5e102bc2e66e48")
        self.assertEqual(" ".join(mnemonic),
                          "model sword civil lunar sustain wasp practice search cloth blame oppose music",
                          "wrong encoding of mnemonic")

    def test_bip39_decode_2(self):
        hex = bip39.hexFromBIP39(
            "manual behave tumble profit swift game recall model anchor survey venture resource frost raccoon gym bullet balcony pumpkin bulk salt tray when today will".split())
        self.assertEqual(hex, "87628fa955edbcbe6cdc74087b57c95bc5d7609a00f111d5b4785f5e7bf478d7",
                          "wrong decoding of mnemonic")

    def test_bip39_encode_2(self):
        mnemonic = bip39.BIP39FromHex("87628fa955edbcbe6cdc74087b57c95bc5d7609a00f111d5b4785f5e7bf478d7")
        self.assertEqual(" ".join(mnemonic),
                          "manual behave tumble profit swift game recall model anchor survey venture resource frost raccoon gym bullet balcony pumpkin bulk salt tray when today will",
                          "wrong encoding of mnemonic")

    def test_bip39_decode_3(self):
        hex = bip39.hexFromBIP39("anim admi aunt approv myst web scen east surg city infant susp".split())
        self.assertEqual(hex, "0900743d056927f1b0222dda452dcd6d", "wrong decoding of mnemonic")


if __name__ == '__main__':
    unittest.main()
