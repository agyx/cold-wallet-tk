#!/usr/bin/env python3

import hashlib
import binascii
import optparse
import getpass

version = "v0.5.0"

words = {}

languages = \
    [
        "english",
        "french",
    ]


class BIP39Dict(object):
    def __init__(self, lang="english"):
        self.words = loadWords(lang)
        pass

    def has(self, word):
        try:
            self.indexOf(word)
            return True
        except ValueError:
            return False

    def indexOf(self, word):
        try:
            return self.words.index(word)
        except ValueError:
            pass
        if len(word) < 4:
            raise ValueError("word not found: {}".format(word))
        index = 0
        for item in self.words:
            if item.startswith(word):
                return index
            index += 1
        raise ValueError("word not found: {}".format(word))

    def wordAt(self, index):
        return self.words[index]


def loadWords(lang="english"):
    global words
    for language in languages:
        if lang == language:
            if lang not in words:
                from bip39words import bip39Words
                words[lang] = bip39Words[lang].split("\n")
            return words[lang]
    raise ValueError("unknown BIP39 language: %s".format(language))


def detectLang(mnemonic):
    for language in languages:
        dic = BIP39Dict(language)
        error = False
        for word in mnemonic:
            if not dic.has(word):
                error = True
                break
        if not error:
            # print("lang = " + language)
            return language
    raise ValueError("could not detect language for given mnemonic")


def rawFromBIP39(mnemonic):
    words = BIP39Dict(detectLang(mnemonic))
    buffer = 0
    result = b""
    mnemonicLen = len(mnemonic)
    if mnemonicLen % 3 != 0:
        raise ValueError("mnemonic size should be a multiple of 3 (%d)" % len(mnemonic))
    for word in mnemonic:
        if not words.has(word):
            raise ValueError("%s is not a valid BIP39 mnemonic word" % word)
        buffer = (buffer << 11) | words.indexOf(word)
    checksumLen = mnemonicLen // 3
    readChecksum = buffer & ((1 << checksumLen) - 1)
    payloadLen = mnemonicLen * 11 - checksumLen
    payload = buffer >> checksumLen
    # print "buffer: %x" % buffer
    for i in range(payloadLen // 8):
        result += chr(payload & 0xFF)
        payload >>= 8
    result = result[::-1]
    m = hashlib.sha256()
    m.update(result)
    verRawChecksum = m.digest()
    verChecksum = 0
    verChecksumLen = 0
    for i in range((checksumLen - 1) // 8 + 1):
        verChecksum = (verChecksum << 8) | verRawChecksum[i]
        verChecksumLen += 8
    verChecksum >>= verChecksumLen - checksumLen
    if readChecksum != verChecksum:
        raise ValueError("bad checksum")
    return result


def longFromBIP39(mnemonic):
    buffer = 0
    for char in rawFromBIP39(mnemonic):
        buffer = (buffer << 8) | ord(char)
    return buffer


def hexFromBIP39(mnemonic):
    result = ""
    for char in rawFromBIP39(mnemonic):
        result += "%02x" % ord(char)
    return result


def BIP39FromRaw(rawSeed, lang="english"):
    words = BIP39Dict(lang)
    seedLen = len(rawSeed) * 8
    m = hashlib.sha256()
    m.update(rawSeed)
    checksum = m.digest()
    entropy = rawSeed + checksum
    bip39SeedLen = (seedLen + seedLen // 32) // 11
    currentLen = 0
    value = 0
    wordList = []
    for byte in entropy:
        currentLen += 8
        value = (value << 8) | byte
        if currentLen >= 11:
            wordIndex = (value >> (currentLen - 11))
            value &= (1 << (currentLen - 11)) - 1
            currentLen -= 11
            # print "wordIndex: %d" % wordIndex
            wordList += [words.wordAt(wordIndex)]
            if len(wordList) == bip39SeedLen:
                return wordList


def BIP39FromHex(hexSeed, lang="english"):
    return BIP39FromRaw(binascii.unhexlify(hexSeed), lang)


def BIP39FromLong(longValue, width=256, lang="english"):
    raw = ""
    buffer = longValue
    for i in range(width // 8):
        raw += chr(buffer & 0xFF)
        buffer >>= 8
    return BIP39FromRaw(raw[::-1], lang)


if __name__ == "__main__":

    parser = optparse.OptionParser()

    parser.add_option("-l", "--lang",
                      action="store", dest="lang", default="english", type="str",
                      help="Language used for BIP39 mnemonic")

    (options, args) = parser.parse_args()

    data = getpass.getpass("seed or BIP39 mnemonic:")

    # noinspection PyBroadException
    try:
        raw = binascii.unhexlify(data)
        BIP39Format = False
    except:
        mnemonic = data.split()
        BIP39Format = True

    try:
        if BIP39Format:
            print(binascii.hexlify(rawFromBIP39(mnemonic)))
        else:
            print((" ".join(BIP39FromRaw(raw, lang=options.lang))))
    except Exception as e:
        print(e.message)

# hex = hexFromBIP39("lawn fluid pretty palm wild much cake grow forget cat bundle team measure same aspect".split())
# print hex
# print BIP39FromHex(hex)
