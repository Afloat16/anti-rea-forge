"""Seal verified Amice VM storage and generate an external-key C++17 loader.

The caller verifies the replacement IR with LLVM before compiling it. Loading
and clearing require exclusive ownership before and after worker execution.
Authenticated VM instructions are plaintext in the authorized process.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import secrets
import struct
import tempfile

from .core import GuardError
from .native_asset import export_native_asset
from .sealed import MAX_ASSET_BYTES, _context, _key, seal_asset


_NAME = r"[A-Za-z$._][A-Za-z0-9$._-]*"
_LOCAL = r"%(?:" + _NAME + r"|[0-9]+)"
_GLOBAL = re.compile(r"^@(" + _NAME + r") = ([^\n]*)$", re.MULTILINE)
_TOKENS = re.compile(r'"(?:[^"\\]|\\.)*"|;[^\n]*|@(' + _NAME + r")")
_INTEGER = r"i(?:1|8|16|32|64)"
_POINTER_TABLE = re.compile(r"private constant \[([1-9][0-9]*) x ptr\] zeroinitializer(?:, align [0-9]+)?")
_FILES = ("releaseguard_native_code.hpp", "releaseguard_native_code.cpp",
          "releaseguard_native_code_asset.hpp", "releaseguard_sealed_asset.hpp")


def _require(condition, message):
    if not condition:
        raise GuardError(message)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _references(text):
    return {match[1] for match in _TOKENS.finditer(text) if match[1] is not None}


def _storage(definition, kind):
    if kind == "bytecode":
        match = re.fullmatch(
            r'private constant \[([1-9][0-9]*) x i8\] c"((?:[^"\\]|\\(?:[0-9A-Fa-f]{2}|\\))*)"'
            r"(?:, align [0-9]+)?", definition)
        _require(match is not None, "Unsupported VM bytecode initializer")
        tokens = re.findall(r"\\(?:[0-9A-Fa-f]{2}|\\)|[^\\]", match[2])
        values = [92 if token == "\\\\" else int(token[1:], 16) if token.startswith("\\")
                  else ord(token) for token in tokens]
        _require(all(value <= 255 for value in values), "VM bytecode contains a non-byte character")
        data = bytes(values)
        count = int(match[1])
        _require(len(data) == count, "VM bytecode initializer length differs from its array")
        return count, data
    match = re.fullmatch(r"private constant \[([1-9][0-9]*) x i64\] \[(.*)\](?:, align [0-9]+)?", definition)
    _require(match is not None, "Unsupported VM descriptor initializer")
    count = int(match[1])
    entries = match[2].split(", ")
    _require(count % 8 == 0 and len(entries) == count
             and all(re.fullmatch(r"i64 -?[0-9]+", value) for value in entries),
             "VM descriptors must contain complete eight-word records")
    values = [int(value[4:]) for value in entries]
    _require(all(-(1 << 63) <= value < (1 << 64) for value in values), "VM descriptor exceeds i64")
    return count, b"".join(struct.pack("<Q", value & ((1 << 64) - 1)) for value in values)


def _wrapper(function, name, runtime, ready, tag):
    header = function["header"]
    match = re.fullmatch(
        r"define (?:(?:dso_local|dso_preemptable|hidden|protected|internal|private|ccc|zeroext|signext|noundef) )*"
        r"(" + _INTEGER + r") @" + re.escape(name) + r"\(([^()]*)\)([^\n]*) \{", header)
    _require(match is not None and function["blocks"] == 1,
             f"Sealed VM requires a single-block integer ABI wrapper: {name}")
    arguments = match[2].split(", ") if match[2] else []
    _require(len(arguments) <= 16 and all(re.fullmatch(
        _INTEGER + r"(?: (?:noundef|zeroext|signext|inreg))* " + _LOCAL, value) for value in arguments),
        f"Sealed VM supports only scalar integer parameters: {name}")
    attributes = header + " " + function["attributes"]
    _require(not re.search(r"\b(readnone|writeonly|argmemonly|inaccessiblememonly|"
                           r"inaccessiblemem_or_argmemonly|speculatable|noreturn|naked|returns_twice|convergent)\b",
                           attributes), f"Unsupported sealed wrapper attribute: {name}")
    _require(all(value in ("read", "readwrite") for value in re.findall(r"\bmemory\(([^)]+)\)", attributes)),
             f"Wrapper memory attributes exclude the ready global: {name}")
    lines = function["body"].splitlines()
    _require(bool(lines) and re.fullmatch(_NAME + r":", lines[0]) is not None,
             f"Sealed VM wrapper requires a named entry block: {name}")
    instructions = [line.strip() for line in lines[1:] if line.strip()]
    opcodes = [re.sub(r"^" + _LOCAL + " = ", "", line).split()[0] for line in instructions]
    _require(not (set(opcodes) - {"alloca", "getelementptr", "store", "load", "add", "shl", "lshr", "or",
                                  "zext", "sext", "call", "trunc", "ret"})
             and opcodes.count("call") == 1 and opcodes.count("ret") == 1
             and re.fullmatch(r"ret " + match[1] + " " + _LOCAL, instructions[-1]) is not None,
             f"Unsupported sealed VM wrapper instructions: {name}")
    _require(re.search(r"^\s*" + _LOCAL + r" = call i64 @" + re.escape(runtime)
                       + r"\(i64 " + _LOCAL + r", ptr " + _LOCAL + r", ptr " + _LOCAL + r"\)$",
                       function["body"], re.MULTILINE) is not None,
             f"Wrapper does not call its verified VM runtime: {name}")
    stem = "rg.sealed." + tag
    _require(stem not in function["body"] and stem not in header, "Sealed wrapper local name collision")
    guarded = (lines[0] + f"\n  %{stem}.ready = load i8, ptr @{ready}, align 1\n"
               f"  %{stem}.allowed = icmp eq i8 %{stem}.ready, 1\n"
               f"  br i1 %{stem}.allowed, label %{stem}.open, label %{stem}.locked\n"
               f"{stem}.open:\n" + "\n".join(lines[1:]) + "\n"
               f"{stem}.locked:\n  ret {match[1]} 0\n")
    return header + "\n" + guarded + "}", match[1]


def _guard_shape(function, descriptor, words):
    """Accept the pinned Amice field-seven guard and its exclusive value uses."""
    body = "\n".join(line.split(";", 1)[0].strip() for line in function["body"].splitlines()
                     if line.split(";", 1)[0].strip())
    records = words // 8
    index = re.findall(r"^%token.index = mul i64 %token.unadd, (-?[0-9]+)$", body, re.MULTILINE)
    _require(words > 0 and words % 8 == 0 and len(index) == 1 and int(index[0]) & 1,
             "Unsupported VM guard token index")
    prefix = f'''%descriptor.index.ok = icmp ult i64 %token.index, {records}
br i1 %descriptor.index.ok, label %descriptor.decode, label %default.return
descriptor.decode:
%descriptor.guard.row = mul i64 %token.index, 8
%descriptor.guard.index = add i64 %descriptor.guard.row, 7
%descriptor.guard.ptr = getelementptr inbounds [{words} x i64], ptr @{descriptor}, i64 0, i64 %descriptor.guard.index
%descriptor.guard.encrypted = load i64, ptr %descriptor.guard.ptr, align 8'''
    decoding = '''%descriptor.guard.unadd = sub i64 %descriptor.guard.encrypted, %descriptor.key.add
%descriptor.guard.unxor = xor i64 %descriptor.guard.unadd, %descriptor.key.mask
%descriptor.guard.plain.amount = and i64 %descriptor.key.rot, 63
%descriptor.guard.plain.right = lshr i64 %descriptor.guard.unxor, %descriptor.guard.plain.amount
%descriptor.guard.plain.neg = sub i64 0, %descriptor.guard.plain.amount
%descriptor.guard.plain.left.amount = and i64 %descriptor.guard.plain.neg, 63
%descriptor.guard.plain.left = shl i64 %descriptor.guard.unxor, %descriptor.guard.plain.left.amount
%descriptor.guard.plain = or i64 %descriptor.guard.plain.left, %descriptor.guard.plain.right'''
    comparison = '''%descriptor.guard.expected = xor i64 %descriptor.guard.expected.mul1, %descriptor.guard.expected.shr31
%descriptor.guard.ok = icmp eq i64 %descriptor.guard.plain, %descriptor.guard.expected
br i1 %descriptor.guard.ok, label %descriptor.ready, label %default.return'''
    _require(all(body.count(part) == 1 for part in (prefix, decoding, comparison)),
             "Unsupported VM descriptor guard shape")
    tokens = re.findall(_LOCAL, body)
    uses = {"descriptor.index.ok": 2, "descriptor.decode": 1, "descriptor.ready": 1,
            "descriptor.guard.row": 2, "descriptor.guard.index": 2,
            "descriptor.guard.ptr": 2, "descriptor.guard.encrypted": 2, "descriptor.guard.unadd": 2,
            "descriptor.guard.unxor": 3, "descriptor.guard.plain.amount": 3,
            "descriptor.guard.plain.right": 2, "descriptor.guard.plain.neg": 2,
            "descriptor.guard.plain.left.amount": 2, "descriptor.guard.plain.left": 2,
            "descriptor.guard.plain": 2, "descriptor.guard.expected": 2, "descriptor.guard.ok": 2}
    _require(all(tokens.count("%" + name) == count for name, count in uses.items()),
             "VM guard values have unsupported additional uses")
    _require(body.splitlines().count("descriptor.ready:") == 1,
             "VM guard has no unique ready block")
    return records


def _loader(storage, ready, payload_bytes, payload_sha256, cpp_namespace):
    declarations = [f"extern unsigned char {ready};"]
    clearing = [f"    {ready} = 0;"]
    copying = []
    offset = 0
    for item in storage:
        ctype = "unsigned char" if item["kind"] == "bytecode" else "std::uint64_t"
        name = item["symbol"]
        declarations.append(f"extern {ctype} {name}[{item['elements']}];")
        clearing.append(f"    OPENSSL_cleanse({name}, sizeof({name}));")
        copying.append(f"    std::memcpy({name}, plaintext.data() + {offset}, sizeof({name}));")
        offset += item["bytes"]
    expected = ", ".join(f"0x{value:02x}" for value in bytes.fromhex(payload_sha256))
    header = '''// Initialize before starting workers and clear after joining them.
#pragma once
#include "releaseguard_sealed_asset.hpp"
namespace releaseguard {
bool initialize_native_code(const native_asset_key& key) noexcept;
void clear_native_code() noexcept;
}  // namespace releaseguard
'''
    source = '''#include "releaseguard_native_code.hpp"
#include "releaseguard_native_code_asset.hpp"
#include <cstdint>

extern "C" {
''' + "\n".join(declarations) + '''
}

namespace releaseguard {
void clear_native_code() noexcept {
''' + "\n".join(clearing) + '''
}

bool initialize_native_code(const native_asset_key& key) noexcept {
    clear_native_code();
    std::vector<unsigned char> plaintext;
    bool authenticated = false;
    try {
        authenticated = open_embedded_asset(key, plaintext);
    } catch (...) {
        if (!plaintext.empty()) OPENSSL_cleanse(plaintext.data(), plaintext.size());
        return false;
    }
    if (!authenticated || plaintext.size() != ''' + str(payload_bytes) + ''') {
        if (!plaintext.empty()) OPENSSL_cleanse(plaintext.data(), plaintext.size());
        return false;
    }
    static constexpr std::array<unsigned char, 32> expected = {''' + expected + '''};
    std::array<unsigned char, 32> actual{};
    unsigned int written = 0;
    const bool exact = EVP_Digest(plaintext.data(), plaintext.size(), actual.data(), &written,
                                  EVP_sha256(), nullptr) == 1 && written == actual.size() &&
                       CRYPTO_memcmp(actual.data(), expected.data(), actual.size()) == 0;
    OPENSSL_cleanse(actual.data(), actual.size());
    if (!exact) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        return false;
    }
''' + "\n".join(copying) + '''
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    ''' + ready + ''' = 1;
    return true;
}
}  // namespace releaseguard
'''
    header = header.replace("namespace releaseguard {", "namespace " + cpp_namespace + " {")
    source = source.replace("namespace releaseguard {", "namespace " + cpp_namespace + " {")
    return header.encode("ascii"), source.encode("ascii")


def seal_virtualized_ir(after_ir_text, vm_coverage, key, product, release, module_id):
    """Return verified-wrapper IR, four flat keyless build files and public metadata.

    vm_coverage is the native-obfuscation observation list produced before this
    edit. All covered wrappers sharing the module runtime receive ready guards.
    Each returned loader has a module-specific C++ namespace and VM storage.
    """
    from .native_obfuscation import _functions

    _key(key)
    aad = _context(product, release, "vm-code", module_id)
    _require(type(after_ir_text) is str and type(vm_coverage) is list and vm_coverage,
             "Expected canonical VM IR and its verified observation list")
    _require(re.search(r"^\s*module\s+asm\b", after_ir_text, re.MULTILINE) is None,
             "Sealed VM does not support module assembly")
    _require(re.search(r"^[ \t]*!llvm\.(?:linker\.options|dependent-libraries)\s*=",
                       after_ir_text, re.MULTILINE) is None,
             "Sealed VM does not support linker metadata")
    filename_pattern = r"^[ \t]*source_filename\s*=.*$"
    filenames = len(re.findall(filename_pattern, after_ir_text, re.MULTILINE))
    _require(filenames <= 1, "Repeated LLVM source filename")
    triple = re.search(r'^target triple = "([^"\n]+)"$', after_ir_text, re.MULTILINE)
    layout = re.search(r'^target datalayout = "([^"\n]+)"$', after_ir_text, re.MULTILINE)
    _require(triple is not None and triple[1].split("-")[0] == "x86_64"
             and "linux" in triple[1].split("-") and "gnux32" not in triple[1].split("-")
             and layout is not None and layout[1].startswith("e"),
             "Sealed VM requires the little-endian x86-64 Linux module runtime")
    functions = _functions(after_ir_text)
    _require(re.search(r'^@"', after_ir_text, re.MULTILINE) is None, "Quoted VM global definitions are unsupported")
    globals_found = list(_GLOBAL.finditer(after_ir_text))
    globals_by_name = {match[1]: match[2] for match in globals_found}
    _require(len(globals_found) == len(globals_by_name), "Duplicate VM globals")
    wrappers, expected = {}, {}
    runtimes = set()
    for observation in vm_coverage:
        _require(type(observation) is dict, "Invalid VM observation")
        coverage = observation.get("vm_coverage")
        if not coverage:
            _require(observation.get("removed") is True and observation.get("name") not in functions,
                     "Every retained original function requires verified VM coverage")
            continue
        _require(type(coverage) is dict and coverage.get("wrapper_replaced") is True
                 and coverage.get("original_body_absent") is True, "Incomplete verified VM coverage")
        name, runtime = observation.get("name"), coverage.get("runtime_function")
        _require(type(name) is str and type(runtime) is str and name in functions
                 and name not in wrappers and runtime in functions,
                 "Missing or repeated covered VM wrapper/runtime")
        wrappers[name] = runtime
        runtimes.add(runtime)
        for field, kind in (("bytecode_globals", "bytecode"), ("descriptor_globals", "descriptor")):
            records = coverage.get(field)
            _require(type(records) is list and records, "Missing covered VM storage")
            for record in records:
                _require(type(record) is dict and type(record.get("name")) is str
                         and re.fullmatch(_NAME, record["name"]) is not None, "Unsupported VM global name")
                symbol = record["name"]
                entry = (kind, record)
                _require(symbol not in expected or expected[symbol] == entry, "Inconsistent shared VM storage coverage")
                expected[symbol] = entry
    _require(wrappers and any(row.get("requested") is True for row in vm_coverage)
             and len(runtimes) == 1, "Sealed VM requires one verified module runtime")

    associated, visited = set(), set()
    pending = list(runtimes)
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        _require(functions[name]["header"].startswith("define private "), "VM runtime helpers must remain private")
        _require('@"' not in functions[name]["body"], "Quoted VM runtime dependencies are unsupported")
        for reference in _references(functions[name]["body"]):
            if reference in functions:
                pending.append(reference)
            elif reference in globals_by_name:
                associated.add(reference)
            else:
                _require(reference.startswith("llvm."), "VM runtime has an external native dependency")
    _require(set(expected) <= associated, "Covered VM storage is disconnected from the runtime")
    pointer_tables = []
    for name, definition in globals_by_name.items():
        if name in expected:
            continue
        if re.match(r"private constant \[[0-9]+ x ptr\]", definition):
            _require(_POINTER_TABLE.fullmatch(definition) is not None, "Native-call table must be zero initialized")
            pointer_tables.append(name)
        else:
            _require(name not in associated and not re.match(r"private constant \[[0-9]+ x i(?:8|64)\]", definition),
                     "Unsealed VM storage or unsupported runtime global")

    tag = _sha(aad + hashlib.sha256(after_ir_text.encode("utf-8")).digest())[:24]
    prefix = "rg_native_code_" + tag
    cpp_namespace = "releaseguard::code_" + tag
    ready = prefix + "_ready"
    _require(prefix not in after_ir_text, "Sealed module symbol collision")
    storage, chunks, renamed = [], [], {}
    for index, (name, (kind, record)) in enumerate(sorted(expected.items())):
        _require(name in globals_by_name, "Covered VM initializer is missing")
        definition = globals_by_name[name]
        count, data = _storage(definition, kind)
        if kind == "bytecode":
            _require(record.get("bytes") == len(data) and record.get("sha256") == _sha(data),
                     "VM bytecode differs from its verified coverage")
        else:
            _require(record.get("words") == count and record.get("ir_sha256") == _sha(definition.encode("utf-8")),
                     "VM descriptor differs from its verified coverage")
        symbol = prefix + "_storage_" + str(index)
        renamed[name] = symbol
        storage.append({"symbol": symbol, "kind": kind, "elements": count, "bytes": len(data)})
        chunks.append(data)
    descriptors = [(index, name) for index, (name, (kind, _)) in enumerate(sorted(expected.items()))
                   if kind == "descriptor"]
    _require(len(descriptors) == 1, "Sealed VM guard requires one descriptor table")
    descriptor_index, descriptor_name = descriptors[0]
    runtime = next(iter(runtimes))
    records = _guard_shape(functions[runtime], descriptor_name, storage[descriptor_index]["elements"])
    runtime_body = functions[runtime]["body"]
    runtime_header = functions[runtime]["header"]
    runtime_pattern = r"^" + re.escape(runtime_header) + r"\n.*?^}"
    old_guard = "  %descriptor.guard.ok = icmp eq i64 %descriptor.guard.plain, %descriptor.guard.expected"

    rewritten = after_ir_text
    guarded = []
    for name, runtime in wrappers.items():
        replacement, return_type = _wrapper(functions[name], name, runtime, ready, tag)
        pattern = r"^" + re.escape(functions[name]["header"]) + r"\n.*?^}"
        rewritten, changed = re.subn(pattern, lambda match: replacement, rewritten,
                                     count=1, flags=re.MULTILINE | re.DOTALL)
        _require(changed == 1, "Could not replace the exact verified VM wrapper")
        guarded.append({"name": name, "return_type": return_type, "locked_return": 0})

    # All original coverage, shape and wrapper checks precede randomization.
    _require(runtime_body.count(old_guard) == 1
             and len(re.findall(runtime_pattern, rewritten, re.MULTILINE | re.DOTALL)) == 1,
             "Could not replace the exact verified VM guard")
    _require(0 < sum(map(len, chunks)) + records * 8 <= MAX_ASSET_BYTES,
             "Sealed VM storage exceeds the native asset size limit")
    guard_symbol = prefix + "_expected_guards"
    guard_data = b"".join(struct.pack("<Q", secrets.randbelow((1 << 64) - 1) + 1) for _ in range(records))
    descriptor_data = bytearray(chunks[descriptor_index])
    for index in range(records):
        descriptor_data[index * 64 + 56:index * 64 + 64] = guard_data[index * 8:index * 8 + 8]
    chunks[descriptor_index] = bytes(descriptor_data)
    storage.append({"symbol": guard_symbol, "kind": "guard_expected", "elements": records,
                    "bytes": len(guard_data)})
    chunks.append(guard_data)
    payload = b"".join(chunks)
    new_guard = (f"  %{prefix}.guard.ptr = getelementptr inbounds [{records} x i64], ptr @{guard_symbol}, "
                 "i64 0, i64 %token.index\n"
                 f"  %{prefix}.guard.expected = load i64, ptr %{prefix}.guard.ptr, align 8\n"
                 f"  %{prefix}.guard.matches = icmp eq i64 %descriptor.guard.encrypted, %{prefix}.guard.expected\n"
                 f"  %{prefix}.guard.nonzero = icmp ne i64 %{prefix}.guard.expected, 0\n"
                 f"  %descriptor.guard.ok = and i1 %{prefix}.guard.matches, %{prefix}.guard.nonzero")
    replacement = runtime_header + "\n" + runtime_body.replace(old_guard, new_guard) + "}"
    rewritten = re.sub(runtime_pattern, lambda match: replacement, rewritten,
                       count=1, flags=re.MULTILINE | re.DOTALL)
    by_original = dict(zip(sorted(expected), storage))

    def replace_global(match):
        item = by_original.get(match[1])
        if item is None:
            return match[0]
        width, alignment = (8, 1) if item["kind"] == "bytecode" else (64, 8)
        return f"@{item['symbol']} = global [{item['elements']} x i{width}] zeroinitializer, align {alignment}"

    rewritten = _GLOBAL.sub(replace_global, rewritten)
    rewritten = _TOKENS.sub(lambda match: "@" + renamed.get(match[1], match[1]) if match[1] else match[0], rewritten)
    declarations = (f"@{ready} = global i8 0, align 1\n"
                    f"@{guard_symbol} = global [{records} x i64] zeroinitializer, align 8\n\n")
    rewritten = re.sub(r"^define ", declarations + "define ", rewritten,
                        count=1, flags=re.MULTILINE)
    rewritten = re.sub(r"^[ \t]*!llvm\.ident\s*=.*(?:\n|$)", "", rewritten, flags=re.MULTILINE)
    rewritten = re.sub(filename_pattern, 'source_filename = "releaseguard-sealed-code"', rewritten,
                       flags=re.MULTILINE)
    if filenames == 0:
        rewritten = 'source_filename = "releaseguard-sealed-code"\n' + rewritten
    document = seal_asset(payload, key, product, release, "vm-code", module_id)
    with tempfile.TemporaryDirectory(prefix="native-code-seal-") as temporary:
        folder = Path(temporary) / "include"
        export_native_asset(document, folder, product, release, "vm-code", module_id)
        helper = (b"#ifndef RELEASEGUARD_SEALED_ASSET_V1_HPP\n#define RELEASEGUARD_SEALED_ASSET_V1_HPP\n"
                  + (folder / "releaseguard/sealed_asset.hpp").read_bytes() + b"\n#endif\n")
        asset = (folder / "releaseguard_asset.hpp").read_bytes().replace(
            b'#include "releaseguard/sealed_asset.hpp"', b'#include "releaseguard_sealed_asset.hpp"')
    payload_sha256 = _sha(payload)
    header, loader = _loader(storage, ready, len(payload), payload_sha256, cpp_namespace)
    files = dict(zip(_FILES, (header, loader, asset, helper)))
    details = {
        "format": "open-release-guard-sealed-native-code/v1", "purpose": "vm-code",
        "payload_bytes": len(payload), "payload_sha256": payload_sha256,
        "ciphertext_bytes": len(payload) + 16, "storage": storage, "ready_symbol": ready,
        "guarded_wrappers": guarded, "zero_native_call_tables": len(pointer_tables),
        "randomized_descriptor_guards": {"scheme": "sealed-random-u64/v1", "records": records,
                                         "descriptor_word_index": 7, "random_bits_per_record": 64,
                                         "nonzero_guard_required": True,
                                         "expected_table_symbol": guard_symbol,
                                         "expected_table_bytes": len(guard_data)},
        "loader_source": _FILES[1], "loader_header": _FILES[0],
        "cpp_namespace": cpp_namespace,
        "required_link_libraries": ["crypto"], "required_cxx_standard": "c++17",
        "authentication": "HKDF-SHA256/AES-256-GCM with trusted caller context",
        "post_authentication_check": "Complete payload SHA-256 before copying VM storage",
        "lifecycle": "Exclusive initialize before starting workers and clear after joining workers",
        "module_scope": "Independent loader namespace and writable storage for each generated module",
        "authorized_process_contains_plaintext_vm_storage": True,
        "stronger_runtime_crypto_replacement_evaluation": "not_performed",
    }
    return rewritten, files, details
