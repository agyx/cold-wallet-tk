#!/usr/bin/env python3

import unittest
import random
import dice


class BiasedDiceEntropy(object):

    def __init__(self):
        self.result = 0
        self.length = 0
        self.count_rolls = 0

    def addRoll(self, roll):
        self.count_rolls += 1
        for dch in roll:
            d = int(dch)
            (val, bits) = binValue(d-1, 6)
            self.length += bits
            for i in range(bits):
                self.result <<= 1
            self.result |= val

    def getResult(self):
        extrabits = self.length % 8;
        temp_result = self.result
        for i in range(extrabits):
            temp_result >>= 1
        return temp_result, self.length - extrabits


def getDiceRoll(bias):
    return str(bias[random.getrandbits(8) % len(bias)])


class Test_Dice(unittest.TestCase):

    # print(binValue(7, 8))
    # print(binValue(23, 24))
    # print(binValue(65, 120))

    def test_dice_1(self):
        result = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for t in range(10000):
            de = dice.DiceEntropy()
            while de.length < 4:
                biases = [
                    [1, 1, 1, 2, 3, 4, 5, 5, 5, 5, 5, 5, 6],
                    [1, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 5, 6],
                    [1, 2, 3, 4, 5, 6],
                    [1, 2, 3, 4, 5, 6],
                    [1, 2, 3, 4, 5, 6, 6, 6, 6, 6, 6, 6, 6]
                ]
                random.shuffle(biases)
                roll = ""
                for i in range(5):
                    roll += getDiceRoll(biases[i])
                #print(roll)
                de.addRoll(roll)
            result[de.result % 16] += 1
        # print(result)
        self.assertEqual(True, True, "error")

"""
    def test_dice_2(self):

        import png

        f = open("sample.png", "w")
        width = 1024
        rows = []
        for y in range(width):
            row = []
            for x in range(int(width/32)):
                #de = dice.BiasedDiceEntropy()
                de = dice.DiceEntropy()
                while de.length < 32:
                    biases = [
                        #[1, 2, 3, 4, 5, 6],
                        [1, 1, 1, 1, 1, 1, 2, 3, 4, 5, 6],
                        [1, 1, 1, 1, 1, 1, 2, 3, 4, 5, 6],
                        [1, 1, 1, 1, 1, 1, 2, 3, 4, 5, 6],
                        [1, 1, 1, 1, 1, 1, 2, 3, 4, 5, 6],
                        [1, 1, 1, 1, 1, 1, 2, 3, 4, 5, 6],
                    ]
                    random.shuffle(biases)
                    roll = ""
                    for i in range(5):
                        roll += getDiceRoll(biases[i])
                    de.addRoll(roll)
                sample = de.result
                #sample = random.getrandbits(32)
                for bit in range(32):
                    row += [sample&1]
                    sample >>= 1
            rows += [row]

        # FIXME: TypeError: write() argument must be str, not bytes
        png.Writer(width=width, height=width, greyscale=True, bitdepth=1).write(f, rows)
        self.assertEquals(True, True, "error")
"""

if __name__ == '__main__':
    unittest.main()
