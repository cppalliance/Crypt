# Copyright 2024 Matt Borland
# Distributed under the Boost Software License, Version 1.0.
# https://www.boost.org/LICENSE_1_0.txt

import sys

def format_hex(s):
    # Remove any whitespace and newlines
    s = s.strip()
    # Split string into pairs of characters
    pairs = [s[i:i+2] for i in range(0, len(s), 2)]
    # Format each pair with 0x prefix and comma
    formatted = ['0x' + pair for pair in pairs]
    # Join with commas
    return ', '.join(formatted)

if __name__ == "__main__":
    # Skip first argument (script name)
    for arg in sys.argv[1:]:
        print(format_hex(arg))
        print()  # Empty line between outputs

