#!/usr/bin/env python3

import unittest
import shamir
import binascii


class Test_Prng(unittest.TestCase):

    def test_shamir_split_3_combine_2_256bits_1(self):

        secret = "522a6ff25f78f3be3aa804f0f1d21a25e0bb98c26001b9082bb5e42a9e1f25ac"

        shamir1 = shamir.Shamir(k=2, n=3, width=256)
        shares = shamir1.split(shamir.longFromRaw(binascii.unhexlify(secret)))

        shamir2 = shamir.Shamir(k=2, n=3, width=256)
        longSecret = shamir2.combine([shares[0], shares[1]])
        self.assertEqual("%064x" % longSecret, secret, "Error in shamir combine part 0 and 1")

        shamir2 = shamir.Shamir(k=2, n=3, width=256)
        longSecret = shamir2.combine([shares[0], shares[2]])
        self.assertEqual("%064x" % longSecret, secret, "Error in shamir combine part 0 and 2")

        shamir2 = shamir.Shamir(k=2, n=3, width=256)
        longSecret = shamir2.combine([shares[1], shares[2]])
        self.assertEqual("%064x" % longSecret, secret, "Error in shamir combine part 1 and 2")

        shamir2 = shamir.Shamir(k=2, n=3, width=256)
        longSecret = shamir2.combine([shares[1], shares[0]])
        self.assertEqual("%064x" % longSecret, secret, "Error in shamir combine part 1 and 0")

        shamir2 = shamir.Shamir(k=2, n=3, width=256)
        longSecret = shamir2.combine([shares[2], shares[0]])
        self.assertEqual("%064x" % longSecret, secret, "Error in shamir combine part 2 and 0")

        shamir2 = shamir.Shamir(k=2, n=3, width=256)
        longSecret = shamir2.combine([shares[2], shares[1]])
        self.assertEqual("%064x" % longSecret, secret, "Error in shamir combine part 2 and 1")

    def test_shamir_cli_1(self):

        secret = "d9708cc98974eb52db969e3f8d3e6b13cbfc02d274baaa5c8b2e32ecdbe3b250"

        shares = shamir.cliSplit(3, 6, secret, lang="english")

        # print shares
        self.assertEqual(shares[0], "717323c0fae83da5019c9fb06365ce575901a08f1701097d08eee1abf200a961fd06daa7",
                         "unexpected share")
        self.assertEqual(shares[1], "9143a2c72d1a5cf97d81579803ea477734cb7cca2ac67d0278de17712b5948c8797d63f9",
                         "unexpected share")
        self.assertEqual(shares[2], "c1837d9c4978c7adb5f52e63ef7406bce37d48ca26d855d6fc015ee7fc60120a26571577",
                         "unexpected share")
        self.assertEqual(shares[3], "011348322ed755a9650db0d3c0c5dd068e30ac53009d3bc6b27cd3faef7b236442e33d30",
                         "unexpected share")
        self.assertEqual(shares[4], "d1d3ba03e4b80aa80a206efd564fe446912d9f3c3f70c829512e693353c1ea8c7c7acbd2",
                         "unexpected share")
        self.assertEqual(shares[5], "d153cae69e7b248ed7f786cea2390d3d65e6ed18c3f609da97564ee482bb6801893cbbe0",
                         "unexpected share")

        def shareTestGenerator(i1, i2, i3):
            def shareGenerator():
                yield shares[i1]
                yield shares[i2]
                yield shares[i3]

            return shareGenerator

        for i1 in range(6):
            for i2 in range(6):
                for i3 in range(6):
                    if i1 != i2 and i2 != i3 and i1 != i3:
                        secretOutput = shamir.cliCombine(shareTestGenerator(i1, i2, i3), lang="english")
                        self.assertEqual(secretOutput, secret,
                                         "secret was not retrieved for shares %d %d %d" % (i1, i2, i3))

    def test_shamir_cli_2(self):

        secret = "canvas advice dolphin piano curious lava forest clump bless trouble pole session frown dismiss quote indoor salad drama"

        shares = shamir.cliSplit(3, 7, secret, lang="english")

        def shareTestGenerator(i1, i2, i3):
            def shareGenerator():
                yield shares[i1]
                yield shares[i2]
                yield shares[i3]

            return shareGenerator

        for i1 in range(6):
            for i2 in range(6):
                for i3 in range(6):
                    if i1 != i2 and i2 != i3 and i1 != i3:
                        secretOutput = shamir.cliCombine(shareTestGenerator(i1, i2, i3), lang="english")
                        self.assertEqual(secretOutput, secret,
                                         "secret was not retrieved for shares %d %d %d" % (i1, i2, i3))

    def test_shamir_cli_3(self):
        secret = "hello world!"

        shares = shamir.cliSplit(3, 5, secret, lang="english")

        # print shares
        self.assertEqual(shares[0],
                         "51f3e5b09dd9bd1fe8f8fc081f08953ce7a65b2898ba8069453e053ece0e7f7bddc9d3c1de52adfda084a0936ebcde903167dbf54dcd099eb61f6af585c5c6295579a319",
                         "unexpected share")
        self.assertEqual(shares[1],
                         "c1a34864ee13a09411a3648799c80e1f13aa7ed7fcaff542bf0dc883169d34187b4dac58cd2bdfcd59ebccff495085720dfc747d3257be16a9e78ddddd80a93be9ee8703",
                         "unexpected share")
        self.assertEqual(shares[2],
                         "f1a34c5a14d250bdb9dda2eb79637d55eae0f1c31a634b0155ca701dc51685f720abcff5e7245faf506ae50e7f675b02e24f8711f8e234fdb1f5d5c6b7e125156c150706",
                         "unexpected share")
        self.assertEqual(shares[3],
                         "e1b3b46124041b855b10640da22b60e208f3cbf3087fb1a989e8be6da4d069b4823478dc414e9250e2515141a5ef331b8eca4b04efa81f323ee9f26174202e7bffcfbb80",
                         "unexpected share")
        self.assertEqual(shares[4],
                         "e183c7b47584bbaa60728d39c922298c5f016b9b31914334ffdbad50fca5029d84b4a7b73d6de316da4490380b58c0ebeb82578edde431e96661d37376c4d1d132eb5660",
                         "unexpected share")

        def shareTestGenerator(i1, i2, i3):
            def shareGenerator():
                yield shares[i1]
                yield shares[i2]
                yield shares[i3]

            return shareGenerator

        for i1 in range(5):
            for i2 in range(5):
                for i3 in range(5):
                    if i1 != i2 and i2 != i3 and i1 != i3:
                        secretOutput = shamir.cliCombine(shareTestGenerator(i1, i2, i3), lang="english")
                        self.assertEqual(secretOutput, secret,
                                         "secret was not retrieved for shares %d %d %d" % (i1, i2, i3))


if __name__ == '__main__':
    unittest.main()
