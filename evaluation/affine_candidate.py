#!/usr/bin/env python3
"""Execute an owned affine-XOR hypothesis on JSON input."""

import json
import sys


def main():
    request = json.load(sys.stdin)
    multiplier, offset = request["model"]
    output = []
    for a, b, state, _size, buffer in request["cases"]:
        value = ((a * multiplier + offset) & ((1 << 64) - 1)) ^ b
        output.append({
            "status": 0,
            "value": value,
            "state": state,
            "buffer": bytes(buffer).hex(),
            "canaries": [165, 90],
            "effect_count": 0,
            "effects": [],
        })
    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
