#!/usr/bin/python

version = "0.1.0"

def rawFromLong(longValue, width=256):
    buffer = longValue
    result = ""
    for i  in range(width/8):
        result += chr(buffer&0xFF)
        buffer >>= 8
    return result[::-1]

def longFromRaw(raw):
    buffer = 0L
    for char in raw:
        buffer = (buffer << 8) | ord(char)
    return buffer

