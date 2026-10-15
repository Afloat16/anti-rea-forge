"""Bounded, read-only inspection of Windows PE image metadata.

This module does not load an image, validate Authenticode, or prove that a
mitigation is effective. Header flags and structural evidence stay separate.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import BinaryIO


_MACHINES = {
    0x014C: "x86",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0x0200: "IA64",
    0x8664: "x64",
    0xA641: "ARM64EC",
    0xA64E: "ARM64X",
    0xAA64: "ARM64",
}
_MAX_SECTIONS = 96
_UINT32_LIMIT = 1 << 32
_DEBUG_ENTRY_SIZE = 28
_MAX_DEBUG_ENTRIES = 4096
# Currently documented PE extended DLL flags: CET_COMPAT and FORWARD_CFI_COMPAT.
_KNOWN_EXTENDED_DLL_CHARACTERISTICS = 0x0001 | 0x0040


def _read_at(stream: BinaryIO, offset: int, size: int, file_size: int) -> bytes:
    """Read one bounded metadata region, never the complete image payload."""
    if offset < 0 or size < 0 or offset > file_size or size > file_size - offset:
        raise ValueError("PE 结构超出文件范围")
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("读取 PE 结构时文件被截断或更改")
    return data


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def audit_pe(path: Path | str) -> dict:
    """Inspect PE32/PE32+ image headers without executing or modifying files.

    Raises ValueError for an invalid or unsupported image structure, and lets
    OSError propagate for filesystem failures. Directory entries beyond the
    standard indices are bounded but are not assigned invented semantics.
    """
    with Path(path).open("rb") as stream:
        file_size = os.fstat(stream.fileno()).st_size
        dos = _read_at(stream, 0, 64, file_size)
        if dos[:2] != b"MZ":
            raise ValueError("缺少 DOS MZ 标记")
        pe_offset = _u32(dos, 0x3C)
        if pe_offset < 64:
            raise ValueError("PE 头部与 DOS 头部重叠")
        header = _read_at(stream, pe_offset, 24, file_size)
        if header[:4] != b"PE\0\0":
            raise ValueError("缺少 PE 标记")

        machine = _u16(header, 4)
        section_count = _u16(header, 6)
        symbols_offset = _u32(header, 12)
        symbol_count = _u32(header, 16)
        optional_size = _u16(header, 20)
        characteristics = _u16(header, 22)
        if not 1 <= section_count <= _MAX_SECTIONS:
            raise ValueError("PE 映像 section 数量必须为 1 至 96")
        if not characteristics & 0x0002:
            raise ValueError("COFF 头部未标记为可执行映像")

        optional_offset = pe_offset + 24
        # SizeOfOptionalHeader is a uint16, so this read is bounded to 65535.
        optional = _read_at(stream, optional_offset, optional_size, file_size)
        if len(optional) < 2:
            raise ValueError("缺少 PE 可选头")
        magic = _u16(optional, 0)
        if magic == 0x010B:
            image_format, directory_offset = "PE32", 96
        elif magic == 0x020B:
            image_format, directory_offset = "PE32+", 112
        else:
            raise ValueError("仅支持 PE32 和 PE32+ 可执行映像")
        if optional_size < directory_offset:
            raise ValueError("PE 可选头长度不足")
        directory_count = _u32(optional, directory_offset - 4)
        if directory_count > (optional_size - directory_offset) // 8:
            raise ValueError("数据目录数量超出可选头长度")

        size_of_headers = _u32(optional, 60)
        dll_characteristics = _u16(optional, 70)
        sections_offset = optional_offset + optional_size
        sections_size = section_count * 40
        sections_end = sections_offset + sections_size
        if size_of_headers < sections_end or size_of_headers > file_size:
            raise ValueError("SizeOfHeaders 未覆盖头部或超出文件范围")
        raw_sections = _read_at(stream, sections_offset, sections_size, file_size)
        sections = []
        for index in range(section_count):
            base = index * 40
            virtual_size = _u32(raw_sections, base + 8)
            virtual_address = _u32(raw_sections, base + 12)
            raw_size = _u32(raw_sections, base + 16)
            raw_offset = _u32(raw_sections, base + 20)
            virtual_span = max(virtual_size, raw_size)
            if virtual_address + virtual_span > _UINT32_LIMIT:
                raise ValueError("section 虚拟范围超出 32 位 RVA 空间")
            if raw_size and (
                raw_offset < size_of_headers
                or raw_offset > file_size
                or raw_size > file_size - raw_offset
            ):
                raise ValueError("section 原始数据与头部重叠或超出文件范围")
            sections.append((virtual_address, virtual_span, raw_offset, raw_size))

        def directory(index: int) -> tuple[int, int]:
            if index >= directory_count:
                return 0, 0
            return struct.unpack_from("<II", optional, directory_offset + index * 8)

        def file_offset_for_rva(address: int, size: int) -> int:
            if address + size > _UINT32_LIMIT:
                raise ValueError("数据目录超出 32 位 RVA 空间")
            matches = set()
            if address < size_of_headers and size <= size_of_headers - address:
                matches.add(address)
            for virtual_address, virtual_span, raw_offset, raw_size in sections:
                if address >= virtual_address:
                    delta = address - virtual_address
                    if delta < virtual_span and size <= virtual_span - delta:
                        if delta <= raw_size and size <= raw_size - delta:
                            matches.add(raw_offset + delta)
            if len(matches) != 1:
                raise ValueError("被审计的数据目录未唯一映射到文件中的完整数据")
            return matches.pop()

        def checked_directory(index: int, *, file_offset: bool = False) -> bool:
            address, size = directory(index)
            if not address and not size:
                return False
            if not address or not size:
                raise ValueError("被审计的数据目录地址与长度不完整")
            if file_offset:
                # Unlike other data directories, Certificate Table uses a
                # file offset, not an RVA. Its existence proves no trust.
                if address % 8 or address > file_size or size > file_size - address:
                    raise ValueError("证书表未按 8 字节对齐或超出文件范围")
                return True
            file_offset_for_rva(address, size)
            return True

        if bool(symbols_offset) != bool(symbol_count):
            raise ValueError("COFF 符号表地址与数量不完整")
        if symbol_count and (
            symbols_offset < size_of_headers
            or symbols_offset > file_size
            or symbol_count * 18 > file_size - symbols_offset
        ):
            raise ValueError("COFF 符号表超出文件范围或与头部重叠")

        evidence = {
            "relocations_present": checked_directory(5),
            "load_config_present": checked_directory(10),
            "debug_directory_present": checked_directory(6),
            "coff_symbols_present": bool(symbol_count),
            "certificate_table_present": checked_directory(4, file_offset=True),
        }
        debug_types = []
        debug_metadata_present = False
        empty_repro_count = 0
        extended_characteristics_count = 0
        if evidence["debug_directory_present"]:
            debug_address, debug_size = directory(6)
            if debug_size % _DEBUG_ENTRY_SIZE:
                raise ValueError("PE 调试目录长度必须为 28 字节条目的整数倍")
            if debug_size // _DEBUG_ENTRY_SIZE > _MAX_DEBUG_ENTRIES:
                raise ValueError("PE 调试目录条目数量超过审计上限")
            debug_offset = file_offset_for_rva(debug_address, debug_size)
            entries = _read_at(stream, debug_offset, debug_size, file_size)
            for entry in struct.iter_unpack("<IIHHIIII", entries):
                reserved, _, major, minor, debug_type, data_size, data_rva, data_offset = entry
                debug_types.append(debug_type)
                if data_size:
                    if (data_offset < size_of_headers or data_offset > file_size
                            or data_size > file_size - data_offset):
                        raise ValueError("PE 调试条目原始数据偏移或长度无效")
                    if data_offset < debug_offset + debug_size and data_offset + data_size > debug_offset:
                        raise ValueError("PE 调试条目原始数据与调试目录重叠")
                    # Unmapped debug payloads may have RVA zero and live in a
                    # file overlay. Otherwise both addresses must agree.
                    if data_rva and file_offset_for_rva(data_rva, data_size) != data_offset:
                        raise ValueError("PE 调试条目 RVA 与文件偏移不一致")
                elif data_rva or data_offset:
                    raise ValueError("空 PE 调试条目包含非空数据地址")

                canonical_header = reserved == 0 and major == 0 and minor == 0
                if debug_type == 20:
                    # The extended DLL characteristics record is a 4-byte
                    # flags value, not CodeView/PDB or source debug data.
                    if data_size != 4:
                        raise ValueError("扩展 DLL characteristics 调试条目必须包含 4 字节标记")
                    extended_flags = _u32(_read_at(stream, data_offset, 4, file_size), 0)
                    if canonical_header and not extended_flags & ~_KNOWN_EXTENDED_DLL_CHARACTERISTICS:
                        extended_characteristics_count += 1
                    else:
                        debug_metadata_present = True
                elif debug_type == 16 and not data_size and canonical_header:
                    # Microsoft permits empty REPRO payloads. Nonempty digest
                    # layouts remain unverified and cannot bypass the gate.
                    empty_repro_count += 1
                else:
                    # Includes CodeView, COFF, embedded PDBs, nonempty REPRO,
                    # and unknown/reserved types, including type zero.
                    debug_metadata_present = True
        evidence["debug_metadata_present"] = debug_metadata_present
        managed = checked_directory(14)
        flags = {
            "dynamic_base": bool(dll_characteristics & 0x0040),
            "nx_compat": bool(dll_characteristics & 0x0100),
            "high_entropy_va": bool(dll_characteristics & 0x0020),
            "guard_cf": bool(dll_characteristics & 0x4000),
        }

        warnings: list[str] = []
        notes = [
            "仅检查 PE 静态头部与结构；安全标记不证明运行时防护有效，也不能阻止反编译或补丁。"
        ]
        if not flags["dynamic_base"]:
            warnings.append("未设置 DYNAMIC_BASE（ASLR 兼容）标记。")
        elif not evidence["relocations_present"]:
            warnings.append("设置了 DYNAMIC_BASE，但未检测到重定位目录。")
        if not flags["nx_compat"]:
            warnings.append("未设置 NX_COMPAT（DEP 兼容）标记。")
        if flags["high_entropy_va"] and image_format == "PE32":
            warnings.append("PE32 设置了 HIGH_ENTROPY_VA；该标记不能证明 64 位高熵 ASLR 生效。")
        if flags["high_entropy_va"] and not flags["dynamic_base"]:
            warnings.append("设置了 HIGH_ENTROPY_VA，但未设置 DYNAMIC_BASE。")
        if flags["guard_cf"]:
            notes.append("CFG 头部标记不证明已完成编译插桩；本审计不验证 Guard 表或运行时执行情况。")
            if not evidence["load_config_present"]:
                warnings.append("设置了 GUARD_CF，但未检测到 Load Config 目录。")
            if not flags["dynamic_base"]:
                warnings.append("设置了 GUARD_CF，但未设置 CFG 所需的 DYNAMIC_BASE 标记。")
        else:
            warnings.append("未设置 GUARD_CF 标记。")
        if debug_metadata_present:
            warnings.append("检测到调试目录中的调试信息或未验证条目；发布前检查 PDB 路径及调试信息。")
        if extended_characteristics_count:
            notes.append("调试目录含有效的 4 字节扩展 DLL characteristics 安全标记；此类条目不等同于 PDB 或源码调试信息，未验证实际运行时防护。")
        if empty_repro_count:
            notes.append("调试目录含空载荷 REPRO 可再现构建标记；此类条目不等同于 PDB 或源码调试信息。")
        if evidence["coff_symbols_present"]:
            warnings.append("检测到 COFF 符号表；发布前检查符号信息。")
        if evidence["certificate_table_present"]:
            notes.append("证书表存在；未验证 Authenticode 签名、证书信任或时间戳。")
        else:
            warnings.append("未检测到嵌入式证书表；这不排除外部目录签名。")
        if managed:
            warnings.append("检测到 CLR 目录；本审计不评估托管代码混淆或元数据保密性。")

        return {
            "machine": _MACHINES.get(machine, f"unknown-0x{machine:04x}"),
            "kind": "dll" if characteristics & 0x2000 else "exe",
            "format": image_format,
            "managed": managed,
            "flags": flags,
            "evidence": evidence,
            "debug_directory_types": debug_types,
            "warnings": warnings,
            "notes": notes,
        }
