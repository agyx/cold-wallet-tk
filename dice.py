#!/usr/bin/env python

#
# Randomness from loaded dice
#
import sys
from prng import Prng


def bin_value(value, range):
    while True:
        pow2 = 1
        bits = 0
        while pow2 * 2 <= range:
            bits += 1
            pow2 *= 2
        if value < pow2:
            return value, bits
        value -= pow2
        range -= pow2


def rank2(value, v1):
    if value < v1:
        return 0, (value, v1)
    else:
        return 1, (v1, value)


def rank3(value, v1, v2):
    if value < v1:
        return 0, (value, v1, v2)
    elif value < v2:
        return 1, (v1, value, v2)
    else:
        return 2, (v1, v2, value)


def rank4(value, v1, v2, v3):
    if value < v1:
        return 0, (value, v1, v2, v3)
    elif value < v2:
        return 1, (v1, value, v2, v3)
    elif value < v3:
        return 2, (v1, v2, value, v3)
    else:
        return 3, (v1, v2, v3, value)


def rank5(value, v1, v2, v3, v4):
    if value < v1:
        return 0, (value, v1, v2, v3, v4)
    elif value < v2:
        return 1, (v1, value, v2, v3, v4)
    elif value < v3:
        return 2, (v1, v2, value, v3, v4)
    elif value < v4:
        return 3, (v1, v2, v3, value, v4)
    else:
        return 4, (v1, v2, v3, v4, value)


def value(d1, d2, d3, d4, d5):
    if d1 == d2 or d1 == d3 or d1 == d4 or d1 == d5 or d2 == d3 or d2 == d4 or d2 == d5 or d3 == d4 or d3 == d5 or d4 == d5:
        return 0, 0
    else:
        (v1, lst) = rank2(d2, d1)
        (v2, lst) = rank3(d3, lst[0], lst[1])
        (v3, lst) = rank4(d4, lst[0], lst[1], lst[2])
        (v4, lst) = rank5(d5, lst[0], lst[1], lst[2], lst[3])
        value = ((v1 * 3 + v2) * 4 + v3) * 5 + v4
        #print(value)
        return bin_value(value, 120)


class DiceEntropy(object):

    def __init__(self):
        self.result = 0L
        self.length = 0
        self.count_rolls = 0

    def addRoll(self, roll):
        self.count_rolls += 1
        d1 = int(roll[0])
        d2 = int(roll[1])
        d3 = int(roll[2])
        d4 = int(roll[3])
        d5 = int(roll[4])
        (val, bits) = value(d1, d2, d3, d4, d5)
        self.length += bits
        self.result <<= bits
        self.result |= val

    def getResult(self):
        extrabits = self.length % 8;
        temp_result = self.result
        temp_result >>= extrabits
        return temp_result, self.length - extrabits


if __name__ == '__main__':

    print("""
Randomness from loaded dice

Use 5 D6 dice, loaded or not. After each roll of all dice:
- Put the dice in line without looking at them
- Starting from the right, remove any dice which have the same value as those on their left
- Roll the removed dice again
- Repeat until all dice have different values
- Enter the result and press return

eg:

5 1 2 1 5 : first throw
5 1 2 : remove 1 5 on the right
5 1 2 4 2 : second throw
5 1 2 4 : remove 2 on the right
5 1 2 4 6 : Ok! Enter 51246
         
    """)

    de = DiceEntropy()
    prng = Prng()

    while True:
        print("roll: ")
        roll = sys.stdin.readline()
        de.addRoll(roll)
        (dice_result, length) = de.getResult()
        rand_value = prng.getRandomLong(length)
        result = rand_value ^ dice_result
        # print("rv={:x}".format(rand_value))
        print("{} rolls, {} bits: {:x}".format(de.count_rolls, length, result))

