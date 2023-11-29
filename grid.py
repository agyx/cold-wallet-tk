from genkey import genKey
from prng import Prng
# from bip39words import bip39Words
import optparse
import getpass
import bip39

def get4chars_word(chaine):
    if len(chaine) < 4:
        return chaine
    return chaine[:4]


if __name__ == "__main__":

    parser = optparse.OptionParser()

    parser.add_option("-l", "--lang",
                      action="store", dest="lang", default="english", type="str",
                      help="Language used for BIP39 mnemonic")

    (options, args) = parser.parse_args()

    userdata = getpass.getpass("Clé de grille? :")
    # userdata_bytes = userdata.encode('utf-8')
    prng = Prng(deterministic=True)
    prng.add_entropy(genKey(userdata))

    words = bip39.loadWords(options.lang)
    wstack = []

    def get_next_word():
        global wstack
        if len(wstack) == 0:
            wdata = prng.getRandomLong(48)
            for _ in range(4):
                wstack += [words[wdata % 2048]]
                wdata //= 2048
        word = wstack.pop()
        return word.upper()


    cols = 24
    raws = 96
    print("    X")
    print(" Y", end="")
    for x in range(cols):
        print(f"  {x:02X} ", end="")
    print()
    for y in range(raws):
        print(f"{y:02X} ", end="")
        for x in range(cols):
            print(f"{get4chars_word(get_next_word()):<4}", end=" ")
        print("")

# encodage: <clé>/<X>/<Y>/<mnemo1(redond.)>/pattern
