"""Bounded, read-only ELF metadata inspection for local release checks.

Layouts follow the System V gABI ELF header and section header definitions:
https://gabi.xinuos.com/elf/02-eheader.html
https://gabi.xinuos.com/elf/03-sheader.html

This is not a loader or a complete ELF validator. Evidence records observed
metadata, not a proof that symbols or debug information cannot be recovered.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import BinaryIO


_MAX_SECTION_HEADERS = 8192
_MAX_PROGRAM_HEADERS = 4096
_MAX_NAME_TABLE_BYTES = 1024 * 1024
_MAX_SECTION_NAME_BYTES = 4096
_MAX_TOTAL_NAME_BYTES = 1024 * 1024
_MACHINES = {
    0: "none",
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    22: "s390",
    40: "ARM",
    50: "IA64",
    62: "x64",
    183: "ARM64",
    243: "RISC-V",
    258: "LoongArch",
}


def _check_range(offset: int, size: int, file_size: int) -> None:
    if offset < 0 or size < 0 or offset > file_size or size > file_size - offset:
        raise ValueError("ELF 结构或 section 数据超出文件范围")


def _read_at(stream: BinaryIO, offset: int, size: int, file_size: int) -> bytes:
    _check_range(offset, size, file_size)
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("读取 ELF 元数据时文件被截断或更改")
    return data


def audit_elf(path: Path | str) -> dict:
    """Inspect ELF32/ELF64 ET_EXEC/ET_DYN headers without running the file.

    Both byte orders are supported. Resource limits and unsupported extended
    numbering raise ValueError; filesystem failures propagate as OSError.
    ET_DYN is reported as ``shared`` even for a position independent executable.
    Missing metadata must not be interpreted as proof that a file is protected.
    """
    with Path(path).open("rb") as stream:
        file_size = os.fstat(stream.fileno()).st_size
        ident = _read_at(stream, 0, 16, file_size)
        if ident[:4] != b"\x7fELF":
            raise ValueError("缺少 ELF 标记")
        elf_class, data_encoding, ident_version = ident[4:7]
        if elf_class not in (1, 2):
            raise ValueError("仅支持 ELF32 和 ELF64")
        if data_encoding not in (1, 2):
            raise ValueError("不支持 ELF 字节序编码")
        if ident_version != 1:
            raise ValueError("不支持 ELF identification 版本")
        prefix = "<" if data_encoding == 1 else ">"
        if elf_class == 1:
            header_format = prefix + "HHIIIIIHHHHHH"
            section_format = prefix + "IIIIIIIIII"
            header_size, section_size, program_size = 52, 40, 32
        else:
            header_format = prefix + "HHIQQQIHHHHHH"
            section_format = prefix + "IIQQQQIIQQ"
            header_size, section_size, program_size = 64, 64, 56
        header = struct.unpack(
            header_format, _read_at(stream, 16, header_size - 16, file_size)
        )
        (
            image_type, machine, version, _, program_offset, sections_offset, _,
            declared_header_size, program_entry_size, program_count,
            section_entry_size, section_count, names_index,
        ) = header
        if image_type not in (2, 3):
            raise ValueError("仅支持 ELF ET_EXEC 和 ET_DYN，其他类型暂不支持")
        if version != 1 or declared_header_size != header_size:
            raise ValueError("不支持 ELF 版本或头部长度")
        if program_count == 0xFFFF or names_index == 0xFFFF:
            raise ValueError("暂不支持 ELF 扩展编号")
        if program_count > _MAX_PROGRAM_HEADERS:
            raise ValueError("ELF program header 数量超过审计上限")
        if program_count:
            if program_entry_size != program_size or program_offset < header_size:
                raise ValueError("ELF program header 长度或偏移无效")
            _check_range(program_offset, program_count * program_size, file_size)
        elif program_offset or program_entry_size not in (0, program_size):
            raise ValueError("ELF program header 数量与偏移或长度不一致")

        notes = [
            "仅检查 ELF 静态元数据；未检测到 section 或符号表不证明无法恢复代码、符号或调试信息。"
        ]
        if image_type == 3:
            notes.append("ET_DYN 按 ELF 类型报告为 shared；该类型也可用于 PIE 可执行程序。")

        if not section_count:
            if sections_offset:
                raise ValueError("暂不支持 ELF 扩展 section 编号")
            if names_index or section_entry_size not in (0, section_size):
                raise ValueError("无 section 表时 section 名称索引或长度无效")
            notes.append("文件未提供 section 表；无法按 section 元数据判断调试信息或静态符号是否已移除。")
            return {
                "format": "ELF32" if elf_class == 1 else "ELF64",
                "endian": "little" if data_encoding == 1 else "big",
                "type": "executable" if image_type == 2 else "shared",
                "machine": _MACHINES.get(machine, f"unknown-0x{machine:04x}"),
                "evidence": {"debug_sections_present": False, "symbol_table_present": False},
                "sections": [],
                "section_table_present": False,
                "section_names_available": False,
                "notes": notes,
            }
        if section_count > _MAX_SECTION_HEADERS:
            raise ValueError("ELF section 数量超过审计上限")
        if section_entry_size != section_size or sections_offset < header_size:
            raise ValueError("ELF section header 长度或偏移无效")
        if names_index >= section_count:
            raise ValueError("ELF section 名称表索引超出 section 数量")
        table_size = section_count * section_size
        table = _read_at(stream, sections_offset, table_size, file_size)
        sections = list(struct.iter_unpack(section_format, table))
        if any(sections[0]):
            raise ValueError("ELF 初始空 section 非空，扩展编号或异常元数据暂不支持")

        file_ranges = []
        for section in sections[1:]:
            _, section_type, _, _, offset, size, _, _, alignment, _ = section
            # Every field of a noninitial SHT_NULL entry except its type is
            # undefined. Ignore the whole inactive entry before validation.
            if section_type == 0:
                continue
            if alignment and alignment & (alignment - 1):
                raise ValueError("ELF section 对齐值必须为零或 2 的幂")
            # SHT_NULL is inactive. SHT_NOBITS has a conceptual file offset
            # and may describe memory much larger than the physical file.
            if section_type == 8:
                continue
            _check_range(offset, size, file_size)
            if size:
                if offset < header_size or (
                    offset < sections_offset + table_size and offset + size > sections_offset
                ):
                    raise ValueError("ELF section 数据与 ELF 头部或 section 表重叠")
                file_ranges.append((offset, offset + size))
        file_ranges.sort()
        if any(left[1] > right[0] for left, right in zip(file_ranges, file_ranges[1:])):
            raise ValueError("ELF section 文件数据互相重叠")

        if names_index:
            names_section = sections[names_index]
            _, section_type, section_flags, _, names_offset, names_size, *_ = names_section
            if section_type != 3:
                raise ValueError("ELF section 名称表不是 SHT_STRTAB")
            if section_flags & 0x800:
                raise ValueError("暂不支持压缩的 ELF section 名称表")
            if names_size > _MAX_NAME_TABLE_BYTES:
                raise ValueError("ELF section 名称表超过审计读取上限")
            names_data = _read_at(stream, names_offset, names_size, file_size)
            if names_data and (names_data[0] or names_data[-1]):
                raise ValueError("ELF section 名称表首尾必须为 NUL")
        else:
            names_data = b""
            if any(section[0] for section in sections if section[1] != 0):
                raise ValueError("ELF 未提供 section 名称表但 section 含有名称索引")
            notes.append("文件未提供 section 名称表；无法通过 section 名称判断调试信息是否已移除。")

        section_names = []
        debug_present = False
        total_name_bytes = 0
        cache: dict[int, bytes] = {0: b""}
        for section in sections:
            if section[1] == 0:
                section_names.append("")
                continue
            name_offset = section[0]
            if name_offset not in cache:
                if name_offset >= len(names_data):
                    raise ValueError("ELF section 名称索引超出名称表")
                end = names_data.find(b"\0", name_offset, name_offset + _MAX_SECTION_NAME_BYTES + 1)
                if end < 0:
                    raise ValueError("ELF section 名称未终止或超过长度上限")
                cache[name_offset] = names_data[name_offset:end]
            name = cache[name_offset]
            total_name_bytes += len(name)
            if total_name_bytes > _MAX_TOTAL_NAME_BYTES:
                raise ValueError("ELF section 名称总长度超过审计输出上限")
            section_names.append(name.decode("utf-8", errors="replace"))
            if section[1] != 0 and (
                name.startswith((b".debug_", b".zdebug_", b".stab"))
                or name in (b".debug", b".zdebug", b".gnu_debugdata")
            ):
                debug_present = True

        return {
            "format": "ELF32" if elf_class == 1 else "ELF64",
            "endian": "little" if data_encoding == 1 else "big",
            "type": "executable" if image_type == 2 else "shared",
            "machine": _MACHINES.get(machine, f"unknown-0x{machine:04x}"),
            "evidence": {
                "debug_sections_present": debug_present,
                "symbol_table_present": any(section[1] == 2 for section in sections),
            },
            "sections": section_names,
            "section_table_present": True,
            "section_names_available": bool(names_index and names_data),
            "notes": notes,
        }
