"""Bounded WebAssembly core-v1 section envelopes and private debug metadata.

This is a framing inspector, not a WebAssembly instruction/type validator. It
never loads a module, follows a debug URL, or decodes custom-section payloads.
The binary grammar permits padded unsigned LEB128 encodings up to five bytes:
https://webassembly.github.io/spec/core/binary/values.html#integers
https://webassembly.github.io/spec/core/binary/modules.html#sections
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import BinaryIO


WASM_MAGIC = b"\0asm"
_HEADER = WASM_MAGIC + b"\1\0\0\0"
_MAX_SECTIONS = 8192
_MAX_CUSTOM_NAME_BYTES = 4096
_MAX_TOTAL_NAME_BYTES = 1024 * 1024
# DataCount precedes Code, and Tag precedes Global, despite their numeric ids.
_SECTION_ORDER = {value: index for index, value in enumerate(
    (1, 2, 3, 4, 5, 13, 6, 7, 8, 9, 12, 10, 11), start=1)}
_PRIVATE_NAMES = {
    "name": "name",
    "sourceMappingURL": "source-map-url",
    "external_debug_info": "external-debug-info",
}


@dataclass(frozen=True)
class _Section:
    index: int
    section_id: int
    start: int
    payload_start: int
    end: int
    private_kind: str | None


def _read_at(stream: BinaryIO, offset: int, length: int, limit: int) -> bytes:
    if offset < 0 or length < 0 or offset > limit or length > limit - offset:
        raise ValueError("WebAssembly section exceeds its payload boundary")
    stream.seek(offset)
    value = stream.read(length)
    if len(value) != length:
        raise ValueError("WebAssembly input was truncated or changed")
    return value


def _u32(stream: BinaryIO, offset: int, limit: int) -> tuple[int, int]:
    """Decode one bounded unsigned LEB32, accepting legal padded spellings."""
    value = 0
    for index in range(5):
        byte = _read_at(stream, offset, 1, limit)[0]
        offset += 1
        if index == 4 and byte & 0xf0:
            raise ValueError("WebAssembly unsigned LEB128 exceeds 32 bits")
        value |= (byte & 0x7f) << (7 * index)
        if not byte & 0x80:
            return value, offset
    raise ValueError("WebAssembly unsigned LEB128 is unterminated")


def _inspect_wasm_stream(stream: BinaryIO, file_size: int) -> tuple[dict, tuple[_Section, ...]]:
    if type(file_size) is not int or file_size < 0:
        raise ValueError("Expected a nonnegative WebAssembly payload size")
    if _read_at(stream, 0, 8, file_size) != _HEADER:
        raise ValueError("Expected a WebAssembly core-v1 module; components and other versions are unsupported")
    sections = []
    private_counts: Counter[str] = Counter()
    linker_counts: Counter[str] = Counter()
    custom_count = total_names = last_order = 0
    seen_standard: set[int] = set()
    seen_private_names: set[str] = set()
    offset = 8
    while offset < file_size:
        if len(sections) >= _MAX_SECTIONS:
            raise ValueError("WebAssembly section count exceeds the inspection budget")
        start = offset
        section_id = _read_at(stream, offset, 1, file_size)[0]
        offset += 1
        if section_id and section_id not in _SECTION_ORDER:
            raise ValueError("Unsupported WebAssembly section id")
        length, payload = _u32(stream, offset, file_size)
        if not length or length > file_size - payload:
            raise ValueError("WebAssembly section is empty or extends beyond the module")
        end = payload + length
        private_kind = None
        if section_id:
            order = _SECTION_ORDER[section_id]
            if section_id in seen_standard or order <= last_order:
                raise ValueError("Duplicate or out-of-order WebAssembly standard section")
            seen_standard.add(section_id)
            last_order = order
        else:
            custom_count += 1
            name_size, name_start = _u32(stream, payload, end)
            if name_size > _MAX_CUSTOM_NAME_BYTES:
                raise ValueError("WebAssembly custom-section name exceeds the inspection budget")
            total_names += name_size
            if total_names > _MAX_TOTAL_NAME_BYTES:
                raise ValueError("WebAssembly custom-section names exceed the total inspection budget")
            raw_name = _read_at(stream, name_start, name_size, end)
            try:
                name = raw_name.decode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise ValueError("Invalid UTF-8 WebAssembly custom-section name") from exc
            # An embedded NUL can be displayed as a truncated alias by tools
            # while engines retain the complete name. Keep that ambiguity out
            # of this conservative inspection/splitting profile.
            if "\0" in name:
                raise ValueError("NUL in a WebAssembly custom-section name is unsupported")
            private_kind = _PRIVATE_NAMES.get(name)
            # Relocatable/linkable modules retain symbol names independently
            # of the optional name section. Recognize this unfinished-build
            # surface without pretending to parse its symbol/relocation tables.
            # These sections are not safe to delete for every linking consumer.
            if name == "linking":
                linker_counts["linking"] += 1
            elif name.startswith("reloc."):
                linker_counts["relocations"] += 1
            if name.startswith((".debug_", ".zdebug_")):
                private_kind = "dwarf"
            if private_kind is not None:
                if name in seen_private_names:
                    raise ValueError("Duplicate WebAssembly private metadata section")
                seen_private_names.add(name)
                private_counts[private_kind] += 1
        sections.append(_Section(len(sections), section_id, start, payload, end, private_kind))
        offset = end
    report = {
        "format": "wasm-core-v1",
        "sections_checked": len(sections),
        "custom_sections_checked": custom_count,
        "private_sections": dict(sorted(private_counts.items())),
        "linker_sections": dict(sorted(linker_counts.items())),
        "evidence": {
            "debug_metadata_present": bool(private_counts),
            "private_symbols_present": bool(private_counts.get("name")),
            "linker_metadata_present": bool(linker_counts),
        },
        "checks": {"section_envelope_validated": True, "full_module_validation_performed": False},
        "notes": [
            "Only the core-v1 section envelope, section order and custom names are inspected; instructions, types and custom payload semantics are not validated.",
            "Recognized private sections are name, .debug_*/.zdebug_*, sourceMappingURL and external_debug_info. Other custom sections are retained without a confidentiality claim.",
            "linking and reloc.* sections are recognized but their tables are not inspected; finish final linking before release or debug separation. Removing name alone can leave recoverable linker symbols.",
            "Public imports/exports, function bodies and runtime data remain observable. Removing metadata does not prevent equivalent logic reconstruction.",
        ],
    }
    return report, tuple(sections)


def audit_wasm_stream(stream: BinaryIO, file_size: int) -> dict:
    """Inspect a stable bounded stream without reading code or custom payloads.

    Unsupported or ambiguous framing raises ValueError. A successful report
    establishes no execution/type validity and includes no user metadata text.
    """
    return _inspect_wasm_stream(stream, file_size)[0]
