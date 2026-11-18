"""Bounded Mach-O release metadata inspection, without loading the binary.

Format references (Apple's primary headers, pinned for review):
https://github.com/apple-oss-distributions/cctools/tree/e0d56624eca2a76c2ace4c21850df9e666de4ca5/include/mach-o
dSYM address-only sections follow LLVM's dsymutil MachOUtils.cpp.
Java's CAFEBABE collision is disambiguated using class-file structure:
https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html

This is a metadata exposure check, not a loader, signature verifier, complete
JVM verifier, or proof that program logic cannot be recovered. Public binding
symbols, instructions, runtime metadata and encoded application data remain.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import BinaryIO


_THIN_MAGICS = {
    b"\xce\xfa\xed\xfe": ("<", 32),
    b"\xfe\xed\xfa\xce": (">", 32),
    b"\xcf\xfa\xed\xfe": ("<", 64),
    b"\xfe\xed\xfa\xcf": (">", 64),
}
_FAT_MAGICS = {b"\xca\xfe\xba\xbe": 32, b"\xca\xfe\xba\xbf": 64}
_SWAPPED_FAT = {b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"}
MACHO_MAGICS = frozenset(_THIN_MAGICS) | frozenset(_FAT_MAGICS) | _SWAPPED_FAT
_MAX_FAT_ARCHES = 64
# Separate structural probing from the supported architecture count: a Java
# major version such as 65 is NOT evidence of an excessive fat architecture list.
_MAX_FAT_PROBE_ARCHES = 4096
_MAX_COMMANDS = 4096
_MAX_COMMAND_BYTES = 8 * 1024 * 1024
_MAX_SECTIONS = 8192
_MAX_SYMBOLS = 262144
_MAX_STRING_BYTES = 8 * 1024 * 1024
_MAX_READ_BYTES = 32 * 1024 * 1024
_MAX_JAVA_BYTES = 8 * 1024 * 1024
_MAX_JAVA_ITEMS = 100000
_CHUNK_BYTES = 65536
_STRIP_COMPATIBILITY_NAME = b"radr://5614542\0"

_LINKEDIT_COMMANDS = {
    0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x80000033, 0x80000034,
}
_DYLIB_COMMANDS = {0xC, 0xD, 0x80000018, 0x8000001F, 0x20, 0x80000023}
_STRING_COMMANDS = {0xE, 0xF, 0x12, 0x13, 0x14, 0x15, 0x8000001C, 0x27, 0x39}
_FIXED_COMMANDS = {
    0x11: 40, 0x1A: 72, 0x1B: 24, 0x24: 16, 0x25: 16,
    0x2A: 16, 0x2F: 16, 0x30: 16,
}


class _Limit(ValueError):
    """A limit cannot be used as evidence that a candidate is another format."""


class _NotFat(ValueError):
    """A structural contradiction, rather than an incomplete fat inspection."""


def _range(offset: int, length: int, size: int) -> None:
    if offset < 0 or length < 0 or offset > size or length > size - offset:
        raise ValueError("Mach-O metadata range exceeds its containing slice")


class _Budget:
    def __init__(self):
        self.read_bytes = 0
        self.symbols = 0

    def read(self, length: int) -> None:
        self.read_bytes += length
        if self.read_bytes > _MAX_READ_BYTES:
            raise _Limit("Mach-O metadata read budget exceeded")


class _Reader:
    def __init__(self, stream: BinaryIO, size: int, budget: _Budget, origin: int = 0):
        self.stream = stream
        self.size = size
        self.budget = budget
        self.origin = origin

    def read(self, offset: int, length: int) -> bytes:
        _range(offset, length, self.size)
        self.budget.read(length)
        self.stream.seek(self.origin + offset)
        data = self.stream.read(length)
        if len(data) != length:
            raise ValueError("Mach-O payload was truncated or changed")
        return data

    def subreader(self, offset: int, size: int):
        _range(offset, size, self.size)
        return _Reader(self.stream, size, self.budget, self.origin + offset)


def _modified_utf8(data: bytes) -> None:
    """Validate class-file CONSTANT_Utf8 code units, including encoded NUL."""
    pos = 0
    while pos < len(data):
        first = data[pos]
        pos += 1
        if 1 <= first <= 0x7F:
            continue
        if first == 0xC0:
            if pos >= len(data) or data[pos] != 0x80:
                raise ValueError("Invalid Java modified UTF-8")
            pos += 1
        elif 0xC2 <= first <= 0xDF:
            if pos >= len(data) or not 0x80 <= data[pos] <= 0xBF:
                raise ValueError("Invalid Java modified UTF-8")
            pos += 1
        elif 0xE0 <= first <= 0xEF:
            if pos + 1 >= len(data) or not 0x80 <= data[pos] <= 0xBF or not 0x80 <= data[pos + 1] <= 0xBF:
                raise ValueError("Invalid Java modified UTF-8")
            if first == 0xE0 and data[pos] < 0xA0:
                raise ValueError("Overlong Java modified UTF-8")
            pos += 2
        else:
            raise ValueError("Invalid Java modified UTF-8")


def _java_class(reader: _Reader) -> None:
    """Prove complete class-file framing; opaque attributes are length bounded.

    Called ONLY after the fat directory or a slice header was structurally
    disproved. It does not verify bytecode or execute a class. Unknown constant
    tags, invalid indices, excessive work and incomplete/trailing bytes fail.
    """
    if reader.size > _MAX_JAVA_BYTES:
        raise _Limit("Java disambiguation byte budget exceeded")
    data = reader.read(0, reader.size)
    pos = 0
    items = 0

    def take(length):
        nonlocal pos
        _range(pos, length, len(data))
        result = data[pos:pos + length]
        pos += length
        return result

    def u2():
        return int.from_bytes(take(2), "big")

    def u4():
        return int.from_bytes(take(4), "big")

    def work(count=1):
        nonlocal items
        items += count
        if items > _MAX_JAVA_ITEMS:
            raise _Limit("Java disambiguation structural budget exceeded")

    if take(4) != b"\xca\xfe\xba\xbe":
        raise ValueError("Not a Java class")
    minor, major = u2(), u2()
    if major < 45 or (major >= 56 and minor not in (0, 65535)):
        raise ValueError("Invalid Java class version")
    count = u2()
    if count < 2:
        raise ValueError("Missing Java constant pool")
    pool = [None] * count
    index = 1
    while index < count:
        work()
        tag = take(1)[0]
        if tag == 1:
            value = take(u2())
            _modified_utf8(value)
        elif tag in (3, 4):
            value = take(4)
        elif tag in (5, 6):
            value = take(8)
            if index + 1 >= count:
                raise ValueError("Truncated two-slot Java constant")
        elif tag in (7, 8, 16, 19, 20):
            value = (u2(),)
        elif tag in (9, 10, 11, 12, 17, 18):
            value = (u2(), u2())
        elif tag == 15:
            value = (take(1)[0], u2())
        else:
            raise ValueError("Unsupported Java constant tag")
        if (tag in (15, 16, 18) and major < 51) or (tag in (19, 20) and major < 53) or (tag == 17 and major < 55):
            raise ValueError("Java constant is inconsistent with its version")
        pool[index] = (tag, value)
        index += 2 if tag in (5, 6) else 1

    def constant(index, tags):
        if not 0 < index < count or pool[index] is None or pool[index][0] not in tags:
            raise ValueError("Invalid Java constant-pool reference")
        return pool[index][1]

    dynamic_indices = []
    for entry in pool[1:]:
        if entry is None:
            continue
        tag, value = entry
        if tag in (7, 8, 16, 19, 20):
            constant(value[0], (1,))
        elif tag in (9, 10, 11):
            constant(value[0], (7,))
            constant(value[1], (12,))
        elif tag == 12:
            constant(value[0], (1,))
            constant(value[1], (1,))
        elif tag in (17, 18):
            dynamic_indices.append(value[0])
            constant(value[1], (12,))
        elif tag == 15:
            kind, reference = value
            if kind in (1, 2, 3, 4):
                tags = (9,)
            elif kind in (5, 8):
                tags = (10,)
            elif kind in (6, 7):
                tags = (10, 11) if major >= 52 else (10,)
            elif kind == 9:
                tags = (11,)
            else:
                raise ValueError("Invalid Java method-handle kind")
            constant(reference, tags)

    access, this_index, super_index = u2(), u2(), u2()
    if access & ~0xF631:
        raise ValueError("Invalid Java class access flags")
    this_name = constant(constant(this_index, (7,))[0], (1,))
    if not this_name or this_name.startswith(b"["):
        raise ValueError("Invalid Java class name")
    if super_index:
        constant(super_index, (7,))
    elif this_name != b"java/lang/Object" and not access & 0x8000:
        raise ValueError("Missing Java superclass")
    interface_count = u2()
    work(interface_count)
    for _ in range(interface_count):
        constant(u2(), (7,))

    bootstrap_count = None

    def attributes(class_level=False):
        nonlocal bootstrap_count
        attr_count = u2()
        work(attr_count)
        for _ in range(attr_count):
            name = constant(u2(), (1,))
            if not name:
                raise ValueError("Empty Java attribute name")
            payload = take(u4())
            if class_level and name == b"BootstrapMethods":
                if bootstrap_count is not None or len(payload) < 2:
                    raise ValueError("Invalid Java bootstrap methods")
                bootstrap_count = int.from_bytes(payload[:2], "big")
                cursor = 2
                work(bootstrap_count)
                for _ in range(bootstrap_count):
                    _range(cursor, 4, len(payload))
                    constant(int.from_bytes(payload[cursor:cursor + 2], "big"), (15,))
                    arguments = int.from_bytes(payload[cursor + 2:cursor + 4], "big")
                    cursor += 4
                    work(arguments)
                    _range(cursor, 2 * arguments, len(payload))
                    for _ in range(arguments):
                        constant(int.from_bytes(payload[cursor:cursor + 2], "big"), (3, 4, 5, 6, 7, 8, 15, 16, 17))
                        cursor += 2
                if cursor != len(payload):
                    raise ValueError("Trailing Java bootstrap method bytes")

    for _ in range(2):  # fields, then methods
        member_count = u2()
        work(member_count)
        for _ in range(member_count):
            u2()  # access flags: not a bytecode/type verifier
            if not constant(u2(), (1,)) or not constant(u2(), (1,)):
                raise ValueError("Empty Java member name or descriptor")
            attributes()
    attributes(class_level=True)
    if any(bootstrap_count is None or index >= bootstrap_count for index in dynamic_indices):
        raise ValueError("Invalid Java bootstrap-method reference")
    if pos != len(data):
        raise ValueError("Trailing bytes after Java class")


def _fat_layout(reader: _Reader, bits: int) -> list[tuple[int, int, int, int]]:
    """Validate a complete directory and every thin header before auditing.

    _NotFat permits Java disambiguation only after excluding native evidence.
    A complete thin header at any declared offset locks the input to Mach-O,
    even if another entry is malformed. _Limit never permits Java fallback.
    """
    native_evidence = False
    try:
        header = reader.read(0, 8)
        count = struct.unpack_from(">I", header, 4)[0]
        stride = 20 if bits == 32 else 32
        if count == 0:
            raise ValueError("Empty Mach-O fat directory")
        # Range contradiction is decisive even for huge counts. A preview Java
        # minor version of 65535 must not be mistaken for a huge fat allocation.
        _range(8, count * stride, reader.size)
        if count > _MAX_FAT_PROBE_ARCHES:
            raise _Limit("Mach-O fat directory probe budget exceeded")
        table = reader.read(8, count * stride)
        minimum = 8 + len(table)
        # Probe the complete bounded directory BEFORE rejecting any one entry.
        # CPU, alignment and declared size may themselves be corrupt; they must
        # not hide a later native slice or authorize a downgrade to Java.
        for index in range(count):
            offset = struct.unpack_from(">I" if bits == 32 else ">Q",
                                        table, index * stride + 8)[0]
            if offset > reader.size or reader.size - offset < 4:
                continue
            magic = reader.read(offset, 4)
            layout = _THIN_MAGICS.get(magic)
            if layout is None:
                continue
            header_size = 28 if layout[1] == 32 else 32
            if reader.size - offset < header_size:
                continue
            reader.read(offset, header_size)
            native_evidence = True
            break
        entries = []
        seen = set()
        for index in range(count):
            if bits == 32:
                cpu, subtype, offset, size, align = struct.unpack_from(">IIIII", table, index * stride)
            else:
                cpu, subtype, offset, size, align, reserved = struct.unpack_from(">IIQQII", table, index * stride)
                if reserved:
                    raise ValueError("Nonzero Mach-O fat reserved field")
            _range(offset, size, reader.size)
            if size < 28 or offset < minimum or align > 63 or offset % (1 << align):
                raise ValueError("Invalid Mach-O fat slice bounds or alignment")
            if (cpu, subtype) in seen:
                raise ValueError("Duplicate Mach-O fat architecture")
            seen.add((cpu, subtype))
            entries.append((offset, size, cpu, subtype))
        previous = minimum
        for offset, size, _, _ in sorted(entries):
            if offset < previous:
                raise ValueError("Overlapping Mach-O fat slices")
            previous = offset + size
        for offset, size, cpu, subtype in entries:
            thin = reader.read(offset, min(size, 32))
            layout = _THIN_MAGICS.get(thin[:4])
            if layout is None:
                raise ValueError("Mach-O fat slice is not a supported thin image")
            endian, width = layout
            if len(thin) < (28 if width == 32 else 32):
                raise ValueError("Truncated Mach-O thin header")
            if struct.unpack_from(endian + "II", thin, 4) != (cpu, subtype):
                raise ValueError("Mach-O fat architecture does not match its slice")
        return entries
    except _Limit:
        raise
    except ValueError as exc:
        if native_evidence:
            raise ValueError("Invalid Mach-O fat metadata after recognizing a thin image") from exc
        raise _NotFat(str(exc)) from exc


def _fat_padding(reader: _Reader, entries, bits: int) -> None:
    # Apple's fat format defines padding as zero. Do not silently bless bytes
    # outside all indexed slices, including a concatenated trailing payload.
    previous = 8 + len(entries) * (20 if bits == 32 else 32)
    for offset, size, _, _ in sorted(entries) + [(reader.size, 0, 0, 0)]:
        while previous < offset:
            length = min(_CHUNK_BYTES, offset - previous)
            if any(reader.read(previous, length)):
                raise ValueError("Nonzero unindexed Mach-O fat padding")
            previous += length
        previous = offset + size


def _name(value: bytes) -> bytes:
    name, separator, padding = value.partition(b"\0")
    if separator and any(padding):
        raise ValueError("Ambiguous Mach-O fixed-width name padding")
    return name


def _command_string(command: bytes, endian: str, minimum: int) -> None:
    if len(command) < minimum:
        raise ValueError("Short Mach-O string command")
    offset = struct.unpack_from(endian + "I", command, 8)[0]
    if not minimum <= offset < len(command) or b"\0" not in command[offset:]:
        raise ValueError("Invalid Mach-O command string")


def _overlap(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return bool(a[1] and b[1] and a[0] < b[0] + b[1] and b[0] < a[0] + a[1])


def _thin(reader: _Reader) -> dict:
    magic = reader.read(0, 4)
    if magic not in _THIN_MAGICS:
        raise ValueError("Missing Mach-O thin magic")
    endian, bits = _THIN_MAGICS[magic]
    header_size = 28 if bits == 32 else 32
    header = reader.read(0, header_size)
    _, cpu, subtype, file_type, ncmds, sizeofcmds, flags = struct.unpack_from(endian + "7I", header)
    if bits == 64 and struct.unpack_from(endian + "I", header, 28)[0]:
        raise ValueError("Nonzero Mach-O reserved header field")
    if file_type not in (1, 2, 6, 7, 8, 10):
        raise ValueError("Unsupported Mach-O file type")
    if flags & 0x80000000:
        raise ValueError("Mach-O shared-cache images are not standalone files")
    if ncmds > _MAX_COMMANDS or sizeofcmds > _MAX_COMMAND_BYTES:
        raise _Limit("Mach-O load-command budget exceeded")
    if not ncmds or ncmds > sizeofcmds // 8:
        raise ValueError("Missing or inconsistent Mach-O load commands")
    commands = reader.read(header_size, sizeofcmds)
    data_start = header_size + sizeofcmds
    sections = 0
    segments = 0
    debug_sections = 0
    compiler_sections = []
    debug_segment = file_type == 10  # MH_DSYM is a debug companion, even if stripped.
    legacy_debug = False
    symtab = None
    dysymtab = None

    def file_data(offset, length):
        _range(offset, length, reader.size)
        if length and offset < data_start:
            raise ValueError("Mach-O data overlaps its header or load commands")

    def exact(command, length):
        if len(command) != length:
            raise ValueError("Invalid Mach-O load-command size")

    cursor = 0
    for _ in range(ncmds):
        if len(commands) - cursor < 8:
            raise ValueError("Truncated Mach-O load command")
        cmd, length = struct.unpack_from(endian + "II", commands, cursor)
        if length < 8 or length % (4 if bits == 32 else 8):
            raise ValueError("Invalid Mach-O load-command alignment")
        _range(cursor, length, len(commands))
        command = commands[cursor:cursor + length]
        cursor += length
        if cmd in (1, 0x19):
            if (cmd == 1) != (bits == 32):
                raise ValueError("Mach-O segment width differs from its header")
            base, stride = (56, 68) if bits == 32 else (72, 80)
            if len(command) < base:
                raise ValueError("Short Mach-O segment command")
            segment_format = "II16sIIIIiiII" if bits == 32 else "II16sQQQQiiII"
            fields = struct.unpack_from(endian + segment_format, command)
            _, _, raw_name, vmaddr, vmsize, fileoff, filesize, _, _, nsects, _ = fields
            segment_name = _name(raw_name)
            if vmaddr + vmsize > 1 << bits:
                raise ValueError("Mach-O segment address overflows")
            _range(fileoff, filesize, reader.size)
            if nsects > _MAX_SECTIONS - sections:
                raise _Limit("Mach-O section budget exceeded")
            exact(command, base + nsects * stride)
            segments += 1
            debug_segment |= segment_name == b"__DWARF"
            for index in range(nsects):
                section_format = "16s16sIIIIIIIII" if bits == 32 else "16s16sQQIIIIIIII"
                fields = struct.unpack_from(endian + section_format, command, base + index * stride)
                raw_section, raw_segment, address, size, offset, align, reloff, nreloc, attributes = fields[:9]
                section_name, section_segment = _name(raw_section), _name(raw_segment)
                if file_type != 1 and section_segment != segment_name:
                    raise ValueError("Mach-O section segment name mismatch")
                if address + size > 1 << bits or align > 63:
                    raise ValueError("Invalid Mach-O section address or alignment")
                is_debug = (attributes & 0x02000000 or section_segment == b"__DWARF"
                            or section_name.startswith((b"__debug_", b"__zdebug_")))
                # dsymutil copies original section addresses but clears their
                # file/relocation offsets. They are address-map placeholders,
                # not bytes at offset zero (LLVM MachOUtils.cpp transferSegmentAndSections).
                shadow = file_type == 10 and offset == 0 and not is_debug
                if shadow:
                    if reloff or nreloc:
                        raise ValueError("Invalid Mach-O dSYM section placeholder")
                elif (attributes & 0xFF) not in (1, 0xC, 0x12):
                    file_data(offset, size)
                    # MH_OBJECT packs its segment immediately after the load
                    # commands. LLVM aligns SectionDataOffset, then adds this
                    # potentially unaligned segment fileoff (MachObjectWriter).
                    alignment_offset = offset - fileoff if file_type == 1 else offset
                    if size and (offset < fileoff or offset + size > fileoff + filesize
                                 or alignment_offset % (1 << align)):
                        raise ValueError("Mach-O section exceeds its segment or is misaligned")
                file_data(reloff, nreloc * 8)
                if is_debug:
                    debug_sections += 1
                # Clang uses __bitcode/__cmdline; Apple's linker packages
                # embedded modules in __bundle. Other __LLVM sections are not
                # assumed to carry IR, nor is a lookalike in another segment.
                # LLVM BitCodeFormat and Apple ld(1), -bitcode_bundle.
                if section_segment == b"__LLVM" and section_name in (
                        b"__bitcode", b"__cmdline", b"__bundle"):
                    compiler_sections.append("__LLVM," + section_name.decode("ascii"))
            sections += nsects
        elif cmd == 2:
            exact(command, 24)
            if symtab is not None:
                raise ValueError("Duplicate Mach-O symbol table")
            symtab = struct.unpack_from(endian + "4I", command, 8)
        elif cmd == 0xB:
            exact(command, 80)
            if dysymtab is not None:
                raise ValueError("Duplicate Mach-O dynamic symbol table")
            dysymtab = struct.unpack_from(endian + "18I", command, 8)
        elif cmd == 3:
            exact(command, 16)
            offset, size = struct.unpack_from(endian + "II", command, 8)
            file_data(offset, size)
            legacy_debug = True
        elif cmd in _LINKEDIT_COMMANDS:
            exact(command, 16)
            offset, size = struct.unpack_from(endian + "II", command, 8)
            file_data(offset, size)
        elif cmd in (0x22, 0x80000022):
            exact(command, 48)
            values = struct.unpack_from(endian + "10I", command, 8)
            for index in range(0, 10, 2):
                file_data(values[index], values[index + 1])
        elif cmd in _DYLIB_COMMANDS:
            _command_string(command, endian, 24)
        elif cmd in _STRING_COMMANDS:
            _command_string(command, endian, 12)
        elif cmd in _FIXED_COMMANDS:
            exact(command, _FIXED_COMMANDS[cmd])
            if (cmd == 0x11 and bits != 32) or (cmd == 0x1A and bits != 64):
                raise ValueError("Mach-O routines width differs from its header")
        elif cmd == 0x80000028:
            exact(command, 24)
            entry, _ = struct.unpack_from(endian + "QQ", command, 8)
            _range(entry, 1, reader.size)
        elif cmd == 0x32:
            if len(command) < 24:
                raise ValueError("Short Mach-O build-version command")
            tools = struct.unpack_from(endian + "I", command, 20)[0]
            exact(command, 24 + tools * 8)
        elif cmd == 0x2D:
            if len(command) < 12:
                raise ValueError("Short Mach-O linker-option command")
            count = struct.unpack_from(endian + "I", command, 8)[0]
            if count > _MAX_COMMANDS:
                raise _Limit("Mach-O linker-option budget exceeded")
            position = 12
            for _ in range(count):
                end = command.find(b"\0", position)
                if end < 0:
                    raise ValueError("Unterminated Mach-O linker option")
                position = end + 1
            if any(command[position:]):
                raise ValueError("Nonzero Mach-O linker-option padding")
        elif cmd in (4, 5):
            position = 8
            while position < len(command):
                _range(position, 8, len(command))
                _, count = struct.unpack_from(endian + "II", command, position)
                position += 8
                _range(position, count * 4, len(command))
                position += count * 4
        elif cmd == 0x16:
            exact(command, 16)
            offset, count = struct.unpack_from(endian + "II", command, 8)
            file_data(offset, count * 4)
        elif cmd in (0x21, 0x2C):
            if (cmd == 0x21) != (bits == 32):
                raise ValueError("Mach-O encryption width differs from its header")
            exact(command, 20 if bits == 32 else 24)
            offset, size, cryptid = struct.unpack_from(endian + "III", command, 8)
            file_data(offset, size)
            if cryptid or (bits == 64 and struct.unpack_from(endian + "I", command, 20)[0]):
                raise ValueError("Encrypted Mach-O metadata cannot be inspected")
        elif cmd == 0x31:
            exact(command, 40)
            offset, size = struct.unpack_from(endian + "QQ", command, 24)
            file_data(offset, size)
            raise ValueError("Mach-O arbitrary note payloads are unsupported")
        else:
            # Includes filesets, legacy fixed-VM records and new metadata-bearing
            # commands whose payloads this version cannot classify.
            raise ValueError("Unsupported Mach-O load command")
    if cursor != sizeofcmds:
        raise ValueError("Mach-O command count leaves unparsed bytes")
    if not segments or not sections or symtab is None:
        raise ValueError("Mach-O section or symbol metadata is unavailable")

    symoff, nsyms, stroff, strsize = symtab
    reader.budget.symbols += nsyms
    if reader.budget.symbols > _MAX_SYMBOLS or strsize > _MAX_STRING_BYTES:
        raise _Limit("Mach-O symbol metadata budget exceeded")
    stride = 12 if bits == 32 else 16
    file_data(symoff, nsyms * stride)
    file_data(stroff, strsize)
    if _overlap((symoff, nsyms * stride), (stroff, strsize)):
        raise ValueError("Overlapping Mach-O symbol and string tables")
    strings = reader.read(stroff, strsize)
    if strings and strings[-1] != 0:
        raise ValueError("Unterminated Mach-O string table")
    symbols = reader.read(symoff, nsyms * stride)

    def named(index):
        if index == 0:
            return False
        if index >= len(strings):
            raise ValueError("Mach-O symbol name exceeds its string table")
        # A final NUL proves termination for every bounded suffix, in linear
        # total work. Repeated .find from attacker-selected indices is quadratic.
        return strings[index] != 0

    private = public = stabs = strip_compatibility_symbols = 0
    for index in range(nsyms):
        name_index, kind, section, descriptor, value = struct.unpack_from(
            endian + ("IBBHI" if bits == 32 else "IBBHQ"), symbols, index * stride)
        has_name = named(name_index)
        if kind & 0xE0:
            stabs += 1
            # Apple strip adds this exact N_OPT record when its output has an
            # indirect symbol table but no remaining locals (cctools misc/strip.c,
            # hack_5614542). It is public compatibility data, not source/debug
            # metadata. Require the complete fixed record and its table context;
            # arbitrary N_OPT records and lookalike names remain debug evidence.
            if (index == 0 and kind == 0x3C and section == 0 and descriptor == 0
                    and value == 0x05614542 and has_name
                    and strings[name_index:name_index + len(_STRIP_COMPATIBILITY_NAME)]
                    == _STRIP_COMPATIBILITY_NAME
                    and dysymtab is not None and dysymtab[:2] == (0, 1)
                    and dysymtab[13] > 0):
                strip_compatibility_symbols += 1
            continue
        # STABS repurpose this byte: N_OSO can store a CPU subtype rather than
        # a section index (Apple mach-o/stab.h). Those entries stay debug evidence.
        if section > sections:
            raise ValueError("Mach-O symbol section index is out of range")
        symbol_type = kind & 0xE
        if symbol_type not in (0, 2, 0xA, 0xC, 0xE):
            raise ValueError("Unknown Mach-O symbol type")
        if (symbol_type == 0xE) != (section != 0):
            raise ValueError("Inconsistent Mach-O symbol section index")
        if symbol_type == 0xA:
            named(value)
        if has_name:
            if kind & 0x10 or not kind & 1:
                private += 1
            else:
                public += 1

    if dysymtab is not None:
        groups = []
        for index in (0, 2, 4):
            start, count = dysymtab[index:index + 2]
            _range(start, count, nsyms)
            if count:
                groups.append((start, count))
        position = 0
        for start, count in sorted(groups):
            if start != position:
                raise ValueError("Overlapping or incomplete Mach-O symbol groups")
            position += count
        if position != nsyms:
            raise ValueError("Incomplete Mach-O dynamic symbol groups")
        # All auxiliary tables are slice-bounded, even though public binding
        # entries themselves are deliberately not treated as private metadata.
        for index, width in ((6, 8), (8, 52 if bits == 32 else 56), (10, 4),
                             (12, 4), (14, 8), (16, 8)):
            offset, count = dysymtab[index:index + 2]
            file_data(offset, count * width)

    return {
        "class": bits, "byte_order": "little" if endian == "<" else "big",
        "cpu_type": cpu, "cpu_subtype": subtype, "file_type": file_type,
        "section_count": sections, "symbol_table_present": True,
        "symbol_count": nsyms, "public_symbols": public,
        "private_symbols": private, "stab_symbols": stabs,
        "strip_compatibility_symbols": strip_compatibility_symbols,
        "debug_sections": debug_sections,
        "compiler_metadata_present": bool(compiler_sections),
        "compiler_metadata_sections": compiler_sections,
        "evidence": {
            "debug_metadata_present": bool(debug_sections or debug_segment or legacy_debug
                                           or stabs > strip_compatibility_symbols),
            "private_symbols_present": bool(private),
        },
    }


def audit_macho_stream(stream: BinaryIO, file_size: int) -> dict | None:
    """Inspect thin 32/64-bit images or canonical BE fat32/fat64 containers.

    Both thin byte orders are supported. Every fat slice is inspected using
    offsets relative to its own bounds. Missing/unsupported metadata and limits
    raise ValueError; I/O errors propagate. No target is executed or extracted.

    None means a complete Java class structure disproved the ambiguous fat32
    interpretation. It never means that an unverified Mach-O passed inspection.
    """
    if type(file_size) is not int or file_size < 0:
        raise ValueError("Expected a nonnegative payload size")
    reader = _Reader(stream, file_size, _Budget())
    magic = reader.read(0, 4)
    if magic in _THIN_MAGICS:
        container = "thin"
        architectures = [_thin(reader)]
    elif magic in _FAT_MAGICS:
        bits = _FAT_MAGICS[magic]
        try:
            entries = _fat_layout(reader, bits)
        except _NotFat:
            if magic != b"\xca\xfe\xba\xbe":
                raise
            _java_class(reader)
            return None
        if len(entries) > _MAX_FAT_ARCHES:
            raise _Limit("Mach-O fat architecture audit budget exceeded")
        _fat_padding(reader, entries, bits)
        architectures = [_thin(reader.subreader(offset, size))
                         for offset, size, _, _ in entries]
        container = "fat32" if bits == 32 else "fat64"
    elif magic in _SWAPPED_FAT:
        raise ValueError("Noncanonical little-endian Mach-O fat headers are unsupported")
    else:
        raise ValueError("Missing Mach-O magic")
    return {
        "format": "macho", "container": container,
        "slice_count": len(architectures), "architectures": architectures,
        "metadata_complete": True,
        "compiler_metadata_present": any(architecture["compiler_metadata_present"]
                                         for architecture in architectures),
        "compiler_metadata_sections": sorted({name for architecture in architectures
                                               for name in architecture["compiler_metadata_sections"]}),
        "evidence": {
            key: any(architecture["evidence"][key] for architecture in architectures)
            for key in ("debug_metadata_present", "private_symbols_present")
        },
    }


def audit_macho(path: Path | str) -> dict | None:
    """Path wrapper for the same read-only, bounded stream inspection."""
    with Path(path).open("rb") as stream:
        return audit_macho_stream(stream, os.fstat(stream.fileno()).st_size)
