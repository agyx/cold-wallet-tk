#!/usr/bin/python

import random
import sys

#a = 31549873
#b = 1872728852
bestn = 0
maxInt = 2147483648*2-1

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
    
def periodOf(a,b,c):
    valdict = {}
    value = 0
    n = 0
    while True: 
        if n%10000 == 0:
            valdict[value] = True
        value = value * a + b
        rbyte = (value & 0xFF) << 24
        value = ((value >> 8) & 0xFFFFFF)| rbyte 
        #value ^= 0xf4f6f5ae
        n += 1
        if n%10000000 == 0 and n > bestn:
            print "%10d %10d %10d: %10d 0x%08x" % (a, b, c, n, value)
        if value == 0:
            return n
        if value in valdict:
            return 0
            
#print "%9d %9x" % (n, value)
    
"""
# 2147483648

a=1401246107
b=1315308013
c=0
print periodOf(a,b,c)
sys.exit()
"""

# 2578057011 4023504493: 2467471149
# 1094823997 3981006681: 3069143756
# 2599326151 1484905072: 3200054045
# 1000798705 3079975534: 3645264326

# 3271078425 2308876641: 2046707014
# 3765049461 1869448784: 2753280937
# 4260349283 4262102746: 3706230478
#  476363961 2740127817: 3879541833

while True:
    a = random.randint(1,maxInt)
    b = random.randint(1,maxInt)
    c = random.randint(0,maxInt)
    n = periodOf(a,b,c)
    if n > bestn:
        print "%10d %10d %10d: %10d" % (a, b, c, n)
        bestn = n