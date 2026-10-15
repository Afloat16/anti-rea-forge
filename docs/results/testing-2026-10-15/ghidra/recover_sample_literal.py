"""Replay one static recovery observed from a source-owned synthetic fixture.

Constants and byte locations were transcribed from Ghidra pseudocode before
reading fixture source or ground truth. This is a fixture-specific experiment,
not a general extractor or a statement of complete semantic recovery.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path


def recover(target: Path) -> dict:
    data = target.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("requires the observed little-endian ELF64 fixture")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    elf_addr = 0x2030
    cipher_offset = None
    for index in range(phnum):
        kind, _, offset, vaddr, _, filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phentsize
        )
        if kind == 1 and vaddr <= elf_addr and elf_addr + 40 <= vaddr + filesz:
            cipher_offset = offset + elf_addr - vaddr
            break
    if cipher_offset is None:
        raise ValueError("observed ciphertext address is unmapped")
    cipher = data[cipher_offset : cipher_offset + 40] + b"\xe7"
    mask = (1 << 64) - 1
    counter = 0
    decoded = bytearray()
    for value in cipher:
        mixed = ((counter ^ 0xE303ED5EF2B60040) + 0x9E3779B97F4A7C15) & mask
        mixed = ((mixed >> 30 ^ mixed) * -0x40A7B892E31B1A47) & mask
        mixed = ((mixed >> 27 ^ mixed) * -0x6B2FB644ECCEEE15) & mask
        key = ((mixed >> 31) ^ mixed) & 255
        if key == 0:
            key = 1
        decoded.append(value ^ key)
        counter = (counter + 0xD6E8FEB86659FD93) & mask
    return {
        "sample_sha256": hashlib.sha256(data).hexdigest(),
        "decoder_entry": "0x00101220",
        "consumer_entry": "0x001012c0",
        "cipher_file_offset": hex(cipher_offset),
        "decoded_hex": decoded.hex(),
        "decoded_text": decoded.rstrip(b"\0").decode("utf-8"),
        "terminated": decoded[-1:] == b"\0",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("sample", type=Path)
    args = parser.parse_args()
    print(json.dumps(recover(args.sample), indent=2))
