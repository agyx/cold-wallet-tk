#!/usr/bin/env python3

version = "0.1.0"


def rawFromLong(longValue, width=256):
    buffer = longValue
    result = b""
    for i in range(width // 8):
        result += bytes([buffer & 0xFF])
        buffer >>= 8
    return result[::-1]


def longFromRaw(raw):
    buffer = 0
    for char in raw:
        buffer = (buffer << 8) | char
    return buffer
