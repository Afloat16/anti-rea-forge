"""Seal verified Amice VM storage and generate an external-key C++17 loader.

The caller verifies the replacement IR with LLVM before compiling it. Loading
and clearing require exclusive ownership before and after worker execution.
Authenticated VM instructions are plaintext in the authorized process.
"""

from __future__ import annotations

from collections import Counter
import hashlib
from importlib import resources
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
_SYNTAX_TOKENS = re.compile(
    r'"(?:[^"\\]|\\.)*"|;[^\n]*'
    r'|[@%!](?:' + _NAME + r'|[0-9]+|"(?:[^"\\]|\\.)*")'
    r'|(?:' + _NAME + r'|[0-9]+)[ \t]*:'
    r'|(' + _NAME + r')')
_INTEGER = r"i(?:1|8|16|32|64)"
_POINTER_TABLE = re.compile(r"private constant \[([1-9][0-9]*) x ptr\] zeroinitializer(?:, align [0-9]+)?")
_RETENTION_GLOBALS = {"llvm.used", "llvm.compiler.used"}
_RETENTION = re.compile(
    r'appending global \[([1-9][0-9]*) x ptr\] \[(ptr @' + _NAME
    + r'(?:, ptr @' + _NAME + r')*)\], section "llvm.metadata"(?:, align [0-9]+)?')
_FORMAT = "open-release-guard-sealed-native-code/v2"
_FILES = ("releaseguard_native_code.hpp", "releaseguard_native_code.cpp",
          "releaseguard_native_code_asset.hpp", "releaseguard_sealed_asset.hpp",
          "releaseguard_secure_buffer.hpp")


def _require(condition, message):
    if not condition:
        raise GuardError(message)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _references(text):
    return {match[1] for match in _TOKENS.finditer(text) if match[1] is not None}


def _require_global_reads(function, message):
    attributes = function["header"] + " " + function["attributes"]
    _require(not re.search(r"\b(speculatable|readnone|writeonly|argmemonly|inaccessiblememonly|"
                           r"inaccessiblemem_or_argmemonly)\b", attributes)
             and all(value in ("read", "readwrite")
                     for value in re.findall(r"\bmemory\(([^)]+)\)", attributes)), message)


def _validate_metadata(text):
    # Named metadata can emit additional object bytes even when it is unrelated
    # to a function body (for example llvm.commandline -> .GCC.command.line).
    # Keep only the compiler's module flags and the ident root removed below.
    for line in text.splitlines():
        if not line.lstrip().startswith("!"):
            continue
        if re.match(r"^![0-9]+ = ", line):
            continue
        _require(re.match(r"^!llvm\.(?:module\.flags|ident) = !\{", line) is not None,
                 "Unsupported sealed VM named metadata")
    syntax = re.sub(r'"(?:[^"\\]|\\.)*"|;[^\n]*', "", text)
    _require(re.search(r"!DI[A-Za-z]+\(", syntax) is None,
             "Sealed VM does not support debug metadata")
    # Unlike named metadata roots, pcsections is attached to a function or
    # instruction. LLVM emits its numbered-node constants as raw object data.
    _require(re.search(r"!pcsections(?![A-Za-z0-9$._-])", syntax) is None,
             "Sealed VM does not support object-emitting attached metadata: pcsections")


def _validate_retention(name, definition, allowed):
    match = _RETENTION.fullmatch(definition)
    _require(match is not None, f"Unsupported VM retention global: {name}")
    references = re.findall(r"ptr @(" + _NAME + r")", match[2])
    _require(len(references) == int(match[1]) and set(references) <= allowed,
             f"VM retention global refers to unverified storage or functions: {name}")


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


def _wrapper(function, name, runtime, ready, tag, storage_symbols):
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
    _require(not re.search(r"\b(speculatable|noreturn|naked|returns_twice|convergent)\b",
                           attributes), f"Unsupported sealed wrapper attribute: {name}")
    _require_global_reads(function, f"Wrapper memory attributes exclude the ready global: {name}")
    _require(_references(function["body"]) == {runtime},
             f"Sealed VM wrapper has unsupported global dependencies: {name}")
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
    checks = [f"  %{stem}.ready = load i8, ptr @{ready}, align 1",
              f"  %{stem}.allowed = icmp eq i8 %{stem}.ready, 1"]
    allowed = f"%{stem}.allowed"
    for index, symbol in enumerate(storage_symbols):
        pointer = f"%{stem}.pointer.{index}"
        checks.extend((f"  {pointer} = load ptr, ptr @{symbol}, align 8",
                       f"  {pointer}.present = icmp ne ptr {pointer}, null",
                       f"  {pointer}.allowed = and i1 {allowed}, {pointer}.present"))
        allowed = pointer + ".allowed"
    guarded = (lines[0] + "\n" + "\n".join(checks) + "\n"
               f"  br i1 {allowed}, label %{stem}.open, label %{stem}.locked\n"
               f"{stem}.open:\n" + "\n".join(lines[1:]) + "\n"
               f"{stem}.locked:\n  ret {match[1]} 0\n")
    return header + "\n" + guarded + "}", match[1]


def _indirect_storage(ir, runtime_functions, storage, prefix):
    """Load authenticated storage pointers at each consuming helper's entry."""
    from .native_obfuscation import _functions

    functions = _functions(ir)
    symbols = {item["symbol"] for item in storage}
    references = {name: _references(functions[name]["body"]) for name in runtime_functions}
    affected = {name for name, values in references.items() if values & symbols}
    while True:
        parents = {name for name, values in references.items() if values & affected}
        if parents <= affected:
            break
        affected.update(parents)
    for name in affected:
        _require_global_reads(functions[name], f"VM helper memory attributes exclude storage bindings: {name}")
    for name in sorted(runtime_functions):
        function = functions[name]
        used = [(index, item["symbol"]) for index, item in enumerate(storage)
                if item["symbol"] in references[name]]
        if not used:
            continue
        lines = function["body"].splitlines()
        _require(lines and re.fullmatch(_NAME + r":", lines[0]) is not None,
                 "VM storage consumer requires a named entry block")
        locals_by_symbol = {symbol: f"%{prefix}.storage.{index}" for index, symbol in used}
        for line in lines[1:]:
            if _references(line) & locals_by_symbol.keys():
                _require(re.search(r"\b(?:getelementptr(?: inbounds)?|ptrtoint|inttoptr|bitcast|addrspacecast)\s*\(",
                                   line) is None,
                         "VM storage has an unsupported constant-expression reference")
        body = _TOKENS.sub(lambda match: locals_by_symbol.get(match[1], match[0]),
                           "\n".join(lines[1:]))
        loads = [f"  {locals_by_symbol[symbol]} = load ptr, ptr @{symbol}, align 8" for _, symbol in used]
        replacement = function["header"] + "\n" + lines[0] + "\n" + "\n".join(loads) + "\n" + body + "\n}"
        pattern = r"^" + re.escape(function["header"]) + r"\n.*?^}"
        ir, changed = re.subn(pattern, lambda match: replacement, ir, count=1,
                             flags=re.MULTILINE | re.DOTALL)
        _require(changed == 1, "Could not redirect the exact VM storage consumer")
    return ir


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
    binding = []
    for item in storage:
        ctype = "unsigned char" if item["kind"] == "bytecode" else "std::uint64_t"
        name = item["symbol"]
        declarations.append(f"extern {ctype}* {name};")
        clearing.append(f"    {name} = nullptr;")
        binding.append(f"    {name} = reinterpret_cast<{ctype}*>("
                       f"memory.buffer->data() + {item['offset_bytes']});")
    expected = ", ".join(f"0x{value:02x}" for value in bytes.fromhex(payload_sha256))
    header = '''// Initialize before starting workers and clear after joining them.
// Automatic module teardown permanently retires the loader; later initialization fails.
#pragma once
#include "releaseguard_sealed_asset.hpp"
namespace releaseguard {
bool initialize_native_code(const native_asset_key& key) noexcept;
void clear_native_code() noexcept;
}  // namespace releaseguard
'''
    source = '''#include "releaseguard_native_code.hpp"
#include "releaseguard_native_code_asset.hpp"
#include "releaseguard_secure_buffer.hpp"
#include <cstdint>
#include <memory>
#include <sys/mman.h>
#include <utility>

extern "C" {
''' + "\n".join(declarations) + '''
}

namespace releaseguard {
namespace {
// This trivially destructible flag remains valid after memory_owner teardown.
// A later global destructor must not access or resurrect its destroyed owner.
bool module_retired = false;
struct memory_owner {
    std::unique_ptr<secure_buffer> buffer;
    ~memory_owner() noexcept {
        clear_native_code();
        module_retired = true;
    }
};
memory_owner& module_memory() noexcept {
    static memory_owner memory;
    return memory;
}
}  // namespace

void clear_native_code() noexcept {
''' + "\n".join(clearing) + '''
    if (!module_retired) module_memory().buffer.reset();
}

bool initialize_native_code(const native_asset_key& key) noexcept {
    clear_native_code();
    if (module_retired) return false;
    try {
        auto pending = std::make_unique<secure_buffer>(''' + str(payload_bytes) + ''',
                                                       secure_buffer_options{true, true});
        if (::madvise(pending->data(), pending->size(), MADV_WIPEONFORK) != 0) return false;
        std::size_t opened = 0;
        if (!open_native_asset_into(key, embedded_asset, pending->data(), pending->size(), opened) ||
            opened != pending->size()) return false;
        static constexpr std::array<unsigned char, 32> expected = {''' + expected + '''};
        std::array<unsigned char, 32> actual{};
        unsigned int written = 0;
        const bool exact = EVP_Digest(pending->data(), pending->size(), actual.data(), &written,
                                      EVP_sha256(), nullptr) == 1 && written == actual.size() &&
                           CRYPTO_memcmp(actual.data(), expected.data(), actual.size()) == 0;
        OPENSSL_cleanse(actual.data(), actual.size());
        if (!exact || !pending->make_read_only()) return false;
        auto& memory = module_memory();
        memory.buffer = std::move(pending);
''' + "\n".join("    " + line for line in binding) + '''
        ''' + ready + ''' = 1;
        return true;
    } catch (...) {
        clear_native_code();
        return false;
    }
}
}  // namespace releaseguard
'''
    header = header.replace("namespace releaseguard {", "namespace " + cpp_namespace + " {")
    source = source.replace("namespace releaseguard {", "namespace " + cpp_namespace + " {")
    return header.encode("ascii"), source.encode("ascii")


def seal_virtualized_ir(after_ir_text, vm_coverage, key, product, release, module_id):
    """Return verified-wrapper IR, flat keyless build files and public metadata.

    vm_coverage is the native-obfuscation observation list produced before this
    edit. All covered wrappers sharing the module runtime receive ready guards.
    Each returned loader has a module-specific C++ namespace and VM storage.
    """
    from .native_obfuscation import _functions

    _key(key)
    aad = _context(product, release, "vm-code", module_id)
    _require(type(after_ir_text) is str and type(vm_coverage) is list and vm_coverage,
             "Expected canonical VM IR and its verified observation list")
    # These constructs emit bytes outside the inventoried VM globals. Inspect
    # syntax tokens across the whole module so same-line module assembly and
    # data attached to a wrapper/private helper cannot survive the closure.
    # Comments, quoted strings, identifiers and labels may use these words.
    syntax_counts = Counter(match[1] for match in _SYNTAX_TOKENS.finditer(after_ir_text)
                            if match[1] is not None)
    _require(not syntax_counts["asm"],
             "Sealed VM does not support module assembly or inline assembly")
    _require(not (syntax_counts["prefix"] or syntax_counts["prologue"]),
             "Sealed VM does not support function prefix or prologue data")
    _require(re.search(r"^[ \t]*!llvm\.(?:linker\.options|dependent-libraries)\s*=",
                       after_ir_text, re.MULTILINE) is None,
             "Sealed VM does not support linker metadata")
    _validate_metadata(after_ir_text)
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
    # Reject definitions that a line-oriented canonical reader cannot inventory,
    # including same-line or split headers. Names such as @define, %define,
    # !define and define: are identifiers, not this top-level keyword.
    definition_count = syntax_counts["define"]
    _require(definition_count == len(functions),
             "Unsupported VM function definition; expected canonical LLVM syntax")
    globals_found = list(_GLOBAL.finditer(after_ir_text))
    _require(sum(line.lstrip().startswith("@") for line in after_ir_text.splitlines()) == len(globals_found),
             "Unsupported VM global definition; expected an exact canonical unquoted name")
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
    # Coverage describes original wrappers, while the compiler can introduce
    # additional definitions. A leftover clone/outlined body must not be emitted
    # in plaintext beside the sealed storage. Only the exact wrapper set and
    # its private runtime dependency closure have been accounted for above.
    _require(set(functions) == set(wrappers) | visited,
             "Uncovered VM function definitions remain outside the verified wrappers and runtime")
    pointer_tables, retention = [], {}
    for name, definition in globals_by_name.items():
        if name in expected:
            continue
        if name in _RETENTION_GLOBALS:
            _require(name not in associated, "VM runtime must not read retention metadata")
            retention[name] = definition
            continue
        if re.match(r"private constant \[[0-9]+ x ptr\]", definition):
            _require(_POINTER_TABLE.fullmatch(definition) is not None, "Native-call table must be zero initialized")
            pointer_tables.append(name)
        else:
            # Do not infer safety from linkage, spelling, reachability or type.
            # An unreferenced internal/unnamed_addr global can still be retained
            # in the object, and an alias can keep an unsealed payload alive.
            raise GuardError("Unsealed VM storage or unsupported runtime global: " + name)
    allowed_retention = set(expected) | set(pointer_tables) | visited | set(wrappers)
    for name, definition in retention.items():
        _validate_retention(name, definition, allowed_retention)

    tag = _sha(_FORMAT.encode("ascii") + b"\0" + aad
               + hashlib.sha256(after_ir_text.encode("utf-8")).digest())[:24]
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
    guard_symbol = prefix + "_expected_guards"
    storage_symbols = [item["symbol"] for item in storage] + [guard_symbol]

    rewritten = after_ir_text
    guarded = []
    for name, runtime in wrappers.items():
        replacement, return_type = _wrapper(functions[name], name, runtime, ready, tag, storage_symbols)
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
    guard_data = b"".join(struct.pack("<Q", secrets.randbelow((1 << 64) - 1) + 1) for _ in range(records))
    descriptor_data = bytearray(chunks[descriptor_index])
    for index in range(records):
        descriptor_data[index * 64 + 56:index * 64 + 64] = guard_data[index * 8:index * 8 + 8]
    chunks[descriptor_index] = bytes(descriptor_data)
    storage.append({"symbol": guard_symbol, "kind": "guard_expected", "elements": records,
                    "bytes": len(guard_data)})
    chunks.append(guard_data)
    payload_parts, offset = [], 0
    for item, chunk in zip(storage, chunks):
        alignment = 1 if item["kind"] == "bytecode" else 8
        padding = (-offset) % alignment
        payload_parts.extend((bytes(padding), chunk))
        offset += padding
        item["offset_bytes"] = offset
        offset += len(chunk)
    payload = b"".join(payload_parts)
    _require(len(payload) <= MAX_ASSET_BYTES, "Aligned sealed VM storage exceeds the native asset size limit")
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
        return f"@{item['symbol']} = global ptr null, align 8"

    rewritten = _GLOBAL.sub(replace_global, rewritten)
    rewritten = _TOKENS.sub(lambda match: "@" + renamed.get(match[1], match[1]) if match[1] else match[0], rewritten)
    declarations = (f"@{ready} = global i8 0, align 1\n"
                    f"@{guard_symbol} = global ptr null, align 8\n\n")
    rewritten = re.sub(r"^define ", declarations + "define ", rewritten,
                        count=1, flags=re.MULTILINE)
    rewritten = _indirect_storage(rewritten, visited, storage, prefix)
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
    secure_buffer = (resources.files("releaseguard") / "data" / "include" / "releaseguard"
                     / "secure_buffer.hpp").read_bytes()
    files = dict(zip(_FILES, (header, loader, asset, helper, secure_buffer)))
    details = {
        "format": _FORMAT, "purpose": "vm-code",
        "payload_bytes": len(payload), "payload_sha256": payload_sha256,
        "ciphertext_bytes": len(payload) + 16, "storage": storage, "ready_symbol": ready,
        "guarded_wrappers": guarded, "zero_native_call_tables": len(pointer_tables),
        "validated_retention_globals": sorted(retention),
        "randomized_descriptor_guards": {"scheme": "sealed-random-u64/v1", "records": records,
                                         "descriptor_word_index": 7, "random_bits_per_record": 64,
                                         "nonzero_guard_required": True,
                                         "expected_table_symbol": guard_symbol,
                                         "expected_table_bytes": len(guard_data)},
        "loader_source": _FILES[1], "loader_header": _FILES[0],
        "cpp_namespace": cpp_namespace,
        "required_link_libraries": ["crypto"], "required_cxx_standard": "c++17",
        "authentication": "HKDF-SHA256/AES-256-GCM with trusted caller context",
        "post_authentication_check": "Complete payload SHA-256 before publishing read-only VM storage",
        "lifecycle": "Exclusive initialize before starting workers and clear after joining workers",
        "module_scope": "Independent loader namespace and owned anonymous mapping for each generated module",
        "memory_protection": {
            "storage": "one anonymous guarded allocation with aligned payload offsets",
            "direct_authenticated_decryption": True,
            "lock_required": True, "dump_exclusion_required": True,
            "fork_wipe_required": True,
            "read_only_before_ready": True, "executable_permission_requested": False,
            "clear_revokes_all_storage_pointers": True,
            "cleanup": "Restore writable, wipe page-rounded payload, unlock and unmap",
            "cleanup_write_restore_failure": "Unmap without a guaranteed explicit userspace wipe",
        },
        "authorized_process_contains_plaintext_vm_storage": True,
        "stronger_runtime_crypto_replacement_evaluation": "not_performed",
    }
    return rewritten, files, details
