"""Validate analyzer-exported bytes against a project-owned, linked x86 ELF."""

import struct

MAX_BYTES = 2 * 1024 * 1024
GATE = "rg_asset_gate"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify_loaded_bytes(image, record):
    """Compare the engine's own dump with file-backed, allocated ELF sections."""
    require(len(image) >= 64 and image[:4] == b"\x7fELF" and image[4] in (1, 2)
            and image[5:7] == b"\x01\x01", "Expected a little-endian ELF32/ELF64")
    is64 = image[4] == 2
    require(struct.unpack_from("<HH", image, 16) == (2, 62 if is64 else 3),
            "Expected an x86 executable with fixed virtual addresses")
    phoff, shoff = struct.unpack_from("<QQ" if is64 else "<II", image, 32 if is64 else 28)
    phsize, phcount, shsize, shcount = struct.unpack_from("<4H", image, 54 if is64 else 42)
    require(phsize == (56 if is64 else 32) and phcount > 0
            and phoff + phsize * phcount <= len(image), "Unsupported ELF program table")
    file_memory = {}
    for position in range(phoff, phoff + phsize * phcount, phsize):
        if is64:
            kind, _, offset, address, _, size = struct.unpack_from("<II4Q", image, position)
        else:
            kind, offset, address, _, size = struct.unpack_from("<5I", image, position)
        if kind != 1 or size == 0:  # PT_LOAD
            continue
        require(offset + size <= len(image) and len(file_memory) + size <= MAX_BYTES,
                "Incomplete or excessive loadable section")
        for i, byte in enumerate(image[offset:offset + size]):
            file_memory[address + i] = byte
    require(shsize == (64 if is64 else 40) and shcount > 0 and shoff + shsize * shcount <= len(image),
            "Unsupported ELF section table")
    blocks = record["blocks"]
    require(isinstance(blocks, list) and 0 < len(blocks) <= 256, "Unexpected memory block count")
    memory = {}
    for block in blocks:
        start = int(block["start"], 16)
        data = bytes.fromhex(block["hex"])
        require(len(data) == block["size"] > 0 and len(memory) + len(data) <= MAX_BYTES,
                "Invalid or excessive initialized memory")
        for offset, byte in enumerate(data):
            address = start + offset
            require(address not in memory, "Overlapping Analyzer memory ranges")
            memory[address] = byte
    require(len(memory) == record["loaded_bytes"], "Incorrect initialized byte count")
    for address, byte in memory.items():
        require(file_memory.get(address) == byte,
                f"Analyzer byte at {address:#x} differs from the file-backed PT_LOAD image")
    checked = 0
    for position in range(shoff, shoff + shsize * shcount, shsize):
        _, kind, flags, address, offset, size = struct.unpack_from("<II4Q" if is64 else "<6I", image, position)
        if not flags & 2 or kind == 8 or size == 0:  # SHF_ALLOC and file-backed data
            continue
        require(offset + size <= len(image), "Incomplete allocated section")
        for i, byte in enumerate(image[offset:offset + size]):
            require(memory.get(address + i) == byte,
                    f"Analyzer did not export allocated-section byte {address + i:#x} exactly")
        checked += size
    require(checked > 0, "No file-backed allocated section verified")
    gate = int(record["gate_entry"], 16)
    prefix = bytes.fromhex(record["gate_prefix_hex"])
    require(record["gate_name"] == GATE and record["gate_instructions"] > 0
            and 6 <= len(prefix) <= record["gate_size"]
            and all(memory.get(gate + i) == byte for i, byte in enumerate(prefix)),
            "Gate disassembly and exported bytes do not agree")
    record["allocated_section_bytes_verified"] = checked
    record["loaded_range_count"] = len(blocks)
    return memory

