"""Build selected-TU Linux objects with a pinned, trusted LLVM 18 pass plugin."""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
import subprocess
import tempfile

from .core import GuardError, _root, write_new
from .native import _assert_scanned_identity
from .split_maps import _destination, _read


_MAX_BYTES = 64 << 20
_PROFILES = {
    "flatten": "function(flattening),verify",
    "split-flatten-substitution": "function(split-basic-blocks,flattening,substitution),verify",
    "virtualize": "default<O2>",
    "sealed-virtualize": "default<O2>",
}
_VM_PROFILES = {"virtualize", "sealed-virtualize"}
_VM_ENVIRONMENT = {
    "AMICE_PASS_ORDER": "VmVirtualize",
    "AMICE_VM_VIRTUALIZE": "true",
    "AMICE_VM_RUNTIME_SCOPE": "module",
    "AMICE_VM_EMIT_MARKERS": "false",
    "AMICE_VM_DUMP_BYTECODE": "false",
    "AMICE_VM_DUMP_LOWERING": "false",
}
_NAME = r'(?:[A-Za-z$._][A-Za-z0-9$._-]*|[0-9]+|"(?:[^"\\]|\\[0-9A-Fa-f]{2})*")'
_DEFINITION = re.compile(r"^define\b.*?@(" + _NAME + r")\(")
_LABEL = re.compile(r"^(" + _NAME + r"):$")
_UNSUPPORTED = re.compile(
    r"^\s*(?:%" + _NAME + r"\s*=\s*)?"
    r"(invoke|callbr|indirectbr|landingpad|catchpad|cleanuppad|catchswitch|catchret|cleanupret|resume)\b",
    re.MULTILINE,
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run(tool: Path, args: list[str], work: Path, environment: dict[str, str]) -> bytes:
    try:
        result = subprocess.run([str(tool), *args], cwd=work, env=environment,
                                capture_output=True, timeout=120, check=True)
    except subprocess.TimeoutExpired as exc:
        raise GuardError(f"LLVM {tool.name} timed out") from exc
    except subprocess.CalledProcessError as exc:
        reason = exc.stderr.decode("utf-8", errors="replace").strip()[:512]
        raise GuardError(f"LLVM {tool.name} failed: {reason}") from exc
    except OSError as exc:
        raise GuardError(f"Could not run LLVM {tool.name}: {exc}") from exc
    return result.stdout


def _without_comments(text: str) -> str:
    return re.sub(r'"(?:[^"\\]|\\.)*"|;[^\n]*',
                  lambda match: "" if match[0].startswith(";") else match[0], text)


def _tokens(text: str) -> str:
    text = re.sub(r"[%@]" + _NAME, " identifier ", text)
    return re.sub(r'"(?:[^"\\]|\\.)*"', "", text)


def _name(symbol: str) -> str:
    if symbol.startswith('"'):
        return re.sub(r"\\([0-9A-Fa-f]{2})", lambda match: chr(int(match[1], 16)), symbol[1:-1])
    return symbol


def _functions(text: str) -> dict[str, dict]:
    """Inspect LLVM's own canonical text, after opt has parsed and verified it."""
    attributes = dict(re.findall(r"^attributes #(\d+) = (.*)$", text, re.MULTILINE))
    result: dict[str, dict] = {}
    lines = iter(_without_comments(text).splitlines())
    for line in lines:
        if not line.startswith("define "):
            continue
        match = _DEFINITION.match(line)
        if not match or not line.endswith("{"):
            raise GuardError("Unsupported canonical LLVM function definition")
        name = _name(match[1])
        if name in result:
            raise GuardError("Duplicate LLVM function definition")
        body_lines = []
        for body_line in lines:
            if body_line == "}":
                break
            body_lines.append(body_line.rstrip())
        else:
            raise GuardError("Unterminated canonical LLVM function")
        body = "\n".join(body_lines).strip() + "\n"
        content = [item.strip() for item in body_lines if item.strip()]
        blocks = sum(bool(_LABEL.fullmatch(item)) for item in content)
        if content and not _LABEL.fullmatch(content[0]):
            blocks += 1
        entry = content[1:] if content and _LABEL.fullmatch(content[0]) else content
        entry_branch = False
        for instruction in entry:
            if _LABEL.fullmatch(instruction):
                break
            if re.match(r"(?:br|switch)\b", instruction):
                entry_branch = True
        groups = re.findall(r"#(\d+)\b", line + "\n" + body)
        attrs = " ".join(attributes.get(group, "") for group in groups)
        result[name] = {"body": body, "header": line, "attributes": attrs,
                        "blocks": blocks, "entry_branch": entry_branch,
                        "sha256": _sha(body.encode("utf-8"))}
    if not result:
        raise GuardError("LLVM input has no defined functions")
    return result


def _preflight(name: str, function: dict, profile: str, required: bool = True) -> None:
    body = function["body"]
    attrs = _tokens(function["header"] + " " + function["attributes"])
    if not required and profile not in _VM_PROFILES and re.search(r"\boptnone\b", attrs):
        return
    match = _UNSUPPORTED.search(body)
    if match:
        raise GuardError(f"Function {name} has unsupported control flow: {match[1]}")
    if re.search(r"\b(optnone|naked|returns_twice|convergent)\b", attrs):
        raise GuardError(f"Function {name} has an unsupported LLVM function attribute")
    if re.search(r"\b(musttail|blockaddress)\b", _tokens(body)) or "@llvm.coro." in body:
        raise GuardError(f"Function {name} has unsupported tail calls, block addresses or coroutines")
    if function["blocks"] > 1 and not function["entry_branch"]:
        raise GuardError(f"Function {name} needs a branch or switch in its multi-block entry")
    if required and function["blocks"] < 2 and profile == "flatten":
        raise GuardError(f"Function {name} has fewer than two basic blocks for flattening")
    if profile == "split-flatten-substitution" or profile in _VM_PROFILES:
        # Restrict the arithmetic profile to the scalar integer/pointer IR tested here.
        tokens = _tokens(function["header"] + "\n" + body)
        if ("<" in tokens or any(int(width) not in (1, 8, 16, 32, 64)
                                  for width in re.findall(r"\bi([0-9]+)\b", tokens))
                or re.search(r"\b(half|bfloat|float|double|fp128|x86_fp80|ppc_fp128|"
                             r"poison|undef|freeze|atomicrmw|cmpxchg|fence|va_arg)\b", tokens)):
            raise GuardError(f"Function {name} exceeds the scalar integer {profile} profile")
    if profile in _VM_PROFILES:
        tokens = _tokens(function["header"] + "\n" + body + "\n" + function["attributes"])
        if re.search(r"\s(?:prefix|prologue)\s", function["header"]):
            raise GuardError(f"Function {name} has unsupported VM prefix or prologue data")
        signature = re.search(r"\b(void|i1|i8|i16|i32|i64|ptr) @" + _NAME + r"\((.*)\)",
                              function["header"])
        parameters = signature[2].split(",") if signature and signature[2].strip() else []
        if (not signature or len(parameters) > 16
                or any(not re.match(r"\s*(?:i1|i8|i16|i32|i64|ptr)\b", parameter) for parameter in parameters)
                or re.search(r"\b(atomic|volatile|asm|addrspace|sret|byval|byref|inalloca|preallocated|"
                             r"swiftself|swifterror|nest|extractvalue|insertvalue)\b|\.\.\.", tokens)
                or re.search(r"\b(?!ccc\b)(?:[A-Za-z0-9_]+cc|cc)\b", attrs)
                or re.search(r"\bcall\b[^\n]*%" + _NAME + r"\(", body)):
            raise GuardError(f"Function {name} exceeds the experimental scalar integer/pointer VM profile")
        if profile == "sealed-virtualize":
            references = re.findall(r"@(" + _NAME + r")", body)
            if re.search(r"\b(ptr|alloca|load|store)\b", tokens) or any(
                    not _name(symbol).startswith("llvm.") for symbol in references):
                raise GuardError(f"Function {name} exceeds the self-contained scalar integer sealed VM profile")


def _dispatchers(function: dict) -> set[tuple[str, str]]:
    """Require an alloca-backed switch and a branch back to its dispatch block."""
    body = function["body"]
    dispatchers = set()
    for match in re.finditer(r"^\s*switch i32 (%" + _NAME + r"), label %" + _NAME + r" \[", body,
                             re.MULTILINE):
        load = re.search(r"^\s*" + re.escape(match[1]) + r" = load i32, ptr (%" + _NAME + r")\b",
                         body[:match.start()], re.MULTILINE)
        if not load or not re.search(r"^\s*" + re.escape(load[1]) + r" = alloca i32\b", body,
                                     re.MULTILINE):
            continue
        labels = re.findall(r"^(" + _NAME + r"):\s*$", body[:match.start()], re.MULTILINE)
        if labels and len(re.findall(r"\bbr label %" + re.escape(labels[-1]) + r"(?:\s|$)", body)) >= 2:
            dispatchers.add((load[1], labels[-1]))
    return dispatchers


def _body_shape(body: str) -> str:
    """Compare instruction bodies while ignoring local SSA and block renaming."""
    names: dict[str, str] = {}
    def replace(match: re.Match) -> str:
        name = match[1] or match[2]
        return names.setdefault(name, f"local{len(names)}") + (":" if match[2] else "")
    normalized = re.sub(r"%(" + _NAME + r")|^(" + _NAME + r"):", replace, body, flags=re.MULTILINE)
    return " ".join(normalized.split())


def _vm_globals(before_text: str, after_text: str) -> dict[str, str]:
    previous = {_name(name) for name in re.findall(r"^@(" + _NAME + r") =", before_text, re.MULTILINE)}
    return {_name(match[1]): match[2] for match in re.finditer(
        r"^@(" + _NAME + r") = (.*)$", after_text, re.MULTILINE) if _name(match[1]) not in previous}


def _vm_coverage(name: str, before: dict[str, dict], after: dict[str, dict],
                 globals_added: dict[str, str]) -> dict | None:
    """Recognize the audited Amice builtin call ABI and its live bytecode decoder.

    This checks applied structure from trusted plugin output. It does not claim
    semantic equivalence or resistance to an independent recovery attempt.
    """
    wrapper = after.get(name)
    if not wrapper or wrapper["blocks"] != 1 or wrapper["sha256"] == before[name]["sha256"]:
        return None
    body = wrapper["body"]
    instructions = [line.strip() for line in body.splitlines() if line.strip() and not _LABEL.fullmatch(line.strip())]
    opcodes = [re.sub(r"^%" + _NAME + r" = ", "", line).split()[0] for line in instructions]
    if (set(opcodes) - {"alloca", "getelementptr", "store", "load", "add", "shl", "lshr", "or",
                       "zext", "sext", "ptrtoint", "call", "trunc", "inttoptr", "ret"}
            or opcodes.count("call") != 1 or opcodes.count("ret") != 1):
        return None
    local = r"(%" + _NAME + r")"
    call = re.search(r"^\s*" + local + r" = call i64 @(" + _NAME + r")\(i64 " + local
                     + r", ptr " + local + r", ptr " + local + r"\)$", body, re.MULTILINE)
    if not call:
        return None
    result, runtime_name, _, return_slots, argument_slots = call.groups()
    runtime_name = _name(runtime_name)
    runtime = after.get(runtime_name)
    if (runtime_name in before or not runtime
            or not re.match(r"define private i64 @" + _NAME + r"\(i64 %" + _NAME
                            + r", ptr %" + _NAME + r", ptr %" + _NAME + r"\)", runtime["header"])):
        return None
    allocations = dict(re.findall(r"^\s*" + local + r" = alloca \[(\d+) x i64\], align 8$", body, re.MULTILINE))
    if (sorted(allocations.values()) != ["16", "2", "3"] or allocations.get(return_slots) != "3"
            or allocations.get(argument_slots) != "16" or opcodes.count("store") != 18):
        return None
    returned = re.fullmatch(r"ret (void|i1|i8|i16|i32|i64|ptr)(?: " + local + r")?", instructions[-1])
    if not returned:
        return None
    if returned[1] != "void" and returned[2] != result:
        conversion = "inttoptr" if returned[1] == "ptr" else "trunc"
        if not re.search(r"^\s*" + re.escape(returned[2] or "") + r" = " + conversion + r" i64 "
                         + re.escape(result) + r" to " + returned[1] + r"$", body, re.MULTILINE):
            return None
    original_shape = _body_shape(before[name]["body"])
    if any(_body_shape(function["body"]) == original_shape for function in after.values()):
        return None

    runtime_body = runtime["body"]
    bytecodes, descriptors = [], []
    for symbol, definition in globals_added.items():
        reference = r"@(?:" + re.escape(symbol) + r'|"' + re.escape(symbol) + r'")'
        bytecode = re.fullmatch(r'private constant \[([1-9][0-9]*) x i8\] c"((?:[^"\\]|\\(?:[0-9A-Fa-f]{2}|\\))*)"(?:,.*)?',
                                definition)
        if bytecode:
            for pointer in re.findall(r"^\s*" + local + r" = getelementptr i8, ptr " + reference
                                       + r", i64 %" + _NAME, runtime_body, re.MULTILINE):
                decoder = re.search(r"^\s*" + local + r" = call i64 @(" + _NAME + r")\(ptr "
                                     + re.escape(pointer) + r", i64 %" + _NAME + r", i64 %" + _NAME
                                     + r", ptr %" + _NAME + r"\)", runtime_body, re.MULTILINE)
                if not decoder or not re.search(r"\bswitch i64 " + re.escape(decoder[1]) + r",", runtime_body):
                    continue
                reader = after.get(_name(decoder[2]))
                if not reader or _name(decoder[2]) in before or not re.search(r"\bload i8, ptr %", reader["body"]):
                    continue
                data = bytes(92 if part == "\\\\" else int(part[1:], 16) if part.startswith("\\") else ord(part)
                             for part in re.findall(r"\\(?:[0-9A-Fa-f]{2}|\\)|[^\\]", bytecode[2]))
                if len(data) != int(bytecode[1]):
                    return None
                bytecodes.append({"name": symbol, "bytes": len(data), "sha256": _sha(data)})
                break
        descriptor = re.match(r"private constant \[([1-9][0-9]*) x i64\] \[", definition)
        if descriptor and int(descriptor[1]) % 8 == 0:
            pointers = re.findall(r"^\s*" + local + r" = getelementptr inbounds \[" + descriptor[1]
                                   + r" x i64\], ptr " + reference + r", i64 0, i64 %" + _NAME,
                                   runtime_body, re.MULTILINE)
            if len(pointers) >= 8 and all(re.search(r"\bload i64, ptr " + re.escape(pointer) + r",", runtime_body)
                                          for pointer in pointers):
                descriptors.append({"name": symbol, "words": int(descriptor[1]),
                                    "ir_sha256": _sha(definition.encode("utf-8"))})
    if not bytecodes or not descriptors:
        return None
    return {"wrapper_replaced": True, "runtime_function": runtime_name,
            "bytecode_globals": bytecodes, "descriptor_globals": descriptors,
            "original_body_absent": True}


def obfuscate_native_ir(input_path: Path | str, output_dir: Path | str,
                        toolchain_dir: Path | str, plugin_path: Path | str,
                        plugin_sha256: str, functions: list[str] | tuple[str, ...],
                        seed: str | None = None, profile: str = "flatten", *,
                        code_key: bytes | None = None, product: str | None = None,
                        release: str | None = None, module_id: str | None = None) -> dict:
    """Create protected.o and a build report from trusted LLVM 18 IR or bitcode.

    toolchain_dir contains opt and llc. The plugin, toolchain, input and build
    parents must be trusted and stable. The plugin operates on every eligible
    definition in the input TU. functions lists the required coverage. Temporary
    IR is private and removed on return. Functional and recovery evaluations are
    performed separately by the application builder.
    """
    if not isinstance(profile, str) or profile not in _PROFILES:
        raise GuardError("Expected profile flatten, split-flatten-substitution, virtualize or sealed-virtualize")
    virtualized = profile in _VM_PROFILES
    if not isinstance(plugin_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", plugin_sha256):
        raise GuardError("Expected a 64-digit hexadecimal plugin SHA-256")
    if seed is not None and (not isinstance(seed, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", seed)):
        raise GuardError("Expected a 32-digit hexadecimal build seed")
    if virtualized and seed is not None:
        raise GuardError(f"The experimental {profile} profile does not support a build seed")
    if profile == "sealed-virtualize":
        from .sealed import _context, _key
        if any(value is None for value in (code_key, product, release, module_id)):
            raise GuardError("The sealed-virtualize profile requires code_key, product, release and module_id")
        _key(code_key)
        _context(product, release, "vm-code", module_id)
    elif any(value is not None for value in (code_key, product, release, module_id)):
        raise GuardError("Code key and context options require the sealed-virtualize profile")
    if (not isinstance(functions, (list, tuple)) or not 1 <= len(functions) <= 128
            or any(not isinstance(name, str) or len(name) > 512
                   or not re.fullmatch(r"[A-Za-z$._][A-Za-z0-9$._-]*", name) for name in functions)
            or len(set(functions)) != len(functions)):
        raise GuardError("Expected 1 to 128 distinct LLVM function symbol names")

    source, plugin = Path(input_path).absolute(), Path(plugin_path).absolute()
    output, tools = _destination(output_dir), _root(toolchain_dir)
    original, identity, _ = _read(source, _MAX_BYTES)
    plugin_data, plugin_identity, _ = _read(plugin, _MAX_BYTES)
    if _sha(plugin_data) != plugin_sha256.lower():
        raise GuardError("LLVM plugin SHA-256 does not match the trusted expected digest")
    build_seed = None if virtualized else (seed.lower() if seed is not None else secrets.token_hex(16))
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(("LLVM_OBF_", "AMICE_"))}
    environment["LC_ALL"] = "C"
    environment.update(_VM_ENVIRONMENT if virtualized else {"LLVM_OBF_SEED": build_seed})

    with tempfile.TemporaryDirectory(dir=output.parent, prefix=".native-obfuscation-") as temporary:
        work = Path(temporary)
        versions = {}
        for name in ("opt", "llc"):
            version = _run(tools / name, ["--version"], work, environment).decode("utf-8", errors="replace")
            match = re.search(r"\bLLVM version (18\.[0-9]+\.[0-9]+)\b", version)
            if not match:
                raise GuardError(f"LLVM {name} must be version 18.x")
            versions[name] = match[1]
        if versions["opt"] != versions["llc"]:
            raise GuardError("LLVM opt and llc versions must match exactly")

        write_new(work / "input.bc", original, secret=True)
        write_new(work / "plugin.so", plugin_data, secret=True)
        _run(tools / "opt", ["-S", "-passes=verify", "-verify-each", "input.bc", "-o", "before.ll"],
             work, environment)
        before_bytes, _, _ = _read(work / "before.ll", _MAX_BYTES)
        before_text = before_bytes.decode("utf-8").replace("\r\n", "\n")
        triple_match = re.search(r'^target triple = "([^"\n]+)"$', before_text, re.MULTILINE)
        triple = triple_match[1] if triple_match else ""
        arch = triple.split("-")[0]
        if arch not in ("x86_64", "i386", "i486", "i586", "i686") or "linux" not in triple.split("-"):
            raise GuardError("Expected an explicit x86 or x86-64 Linux target triple")
        if virtualized:
            if arch != "x86_64" or "gnux32" in triple.split("-"):
                raise GuardError(f"The experimental {profile} profile requires an x86-64 Linux target")
            if re.search(r'^@(?:llvm\.global\.annotations|"llvm\.global\.annotations")\s*=', before_text,
                         re.MULTILINE):
                raise GuardError("VM profiles reject function annotations that can override their configuration")
            if profile == "sealed-virtualize" and re.search(r"^@", before_text, re.MULTILINE):
                raise GuardError("Sealed VM input must be a dedicated computation unit without original global storage")
            if profile == "sealed-virtualize" and re.search(r"^module asm\b", before_text, re.MULTILINE):
                raise GuardError("Sealed VM input cannot contain module-level assembly")
            if profile == "sealed-virtualize" and re.search(
                    r"^!llvm\.(?:linker\.options|dependent-libraries)\s*=", before_text, re.MULTILINE):
                raise GuardError("Sealed VM input cannot contain embedded linker dependencies")
        before = _functions(before_text)
        for name in functions:
            if name not in before:
                raise GuardError(f"Required LLVM function is missing: {name}")
        for name, function in before.items():
            _preflight(name, function, profile, required=name in functions)

        pipeline = _PROFILES[profile]
        _run(tools / "opt", ["-S", "-load-pass-plugin=" + str(work / "plugin.so"),
                              "-passes=" + pipeline, "-verify-each", "before.ll", "-o", "after.ll"],
             work, environment)
        after_bytes, _, _ = _read(work / "after.ll", _MAX_BYTES)
        after_text = after_bytes.decode("utf-8").replace("\r\n", "\n")
        after = _functions(after_text)
        if not virtualized and set(before) != set(after):
            raise GuardError("LLVM transformation unexpectedly changed the function definition set")
        globals_added = _vm_globals(before_text, after_text) if virtualized else {}
        observations = []
        for name in sorted(before):
            current = after.get(name)
            changed = current is None or before[name]["sha256"] != current["sha256"]
            dispatchers = _dispatchers(current) if current else set()
            new_dispatchers = dispatchers - _dispatchers(before[name])
            coverage = _vm_coverage(name, before, after, globals_added) if virtualized else None
            if virtualized and name in functions and not coverage:
                raise GuardError(f"Required function was skipped or has no verified VM wrapper/runtime/bytecode: {name}")
            if not virtualized and name in functions and (not changed or not new_dispatchers):
                raise GuardError(f"Required function was skipped or has no verified dispatcher: {name}")
            observation = {"name": name, "requested": name in functions, "changed": changed,
                           "dispatcher": bool(dispatchers), "new_dispatchers": len(new_dispatchers),
                           "before_sha256": before[name]["sha256"],
                           "after_sha256": current["sha256"] if current else None,
                           "blocks_before": before[name]["blocks"], "blocks_after": current["blocks"] if current else 0}
            if virtualized:
                observation.update(vm_coverage=coverage, removed=current is None)
            observations.append(observation)

        additional_files: dict[str, bytes] = {}
        code_seal = None
        codegen_input, codegen_bytes = "after.ll", after_bytes
        if profile == "sealed-virtualize":
            from .native_code_seal import seal_virtualized_ir
            replacement, additional_files, code_seal = seal_virtualized_ir(
                after_text, observations, code_key, product, release, module_id)
            if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name)
                   or name in {"protected.o", "report.json"} or type(data) is not bytes
                   for name, data in additional_files.items()):
                raise GuardError("Invalid sealed VM build artifact")
            write_new(work / "sealed.ll", replacement.encode("utf-8"), secret=True)
            _run(tools / "opt", ["-S", "-passes=verify", "-verify-each", "sealed.ll", "-o", "sealed-verified.ll"],
                 work, environment)
            codegen_input = "sealed-verified.ll"
            codegen_bytes, _, _ = _read(work / codegen_input, _MAX_BYTES)

        _run(tools / "llc", ["-O=2", "-relocation-model=pic", "-filetype=obj", codegen_input, "-o", "protected.o"],
             work, environment)
        artifact, _, _ = _read(work / "protected.o", _MAX_BYTES)
        elf_class, machine = (2, 62) if arch == "x86_64" else (1, 3)
        if (len(artifact) < (64 if elf_class == 2 else 52)
                or artifact[:7] != b"\x7fELF" + bytes((elf_class, 1, 1))
                or struct.unpack_from("<HH", artifact, 16) != (1, machine)):
            raise GuardError("LLVM code generation did not produce the expected relocatable ELF object")
        _assert_scanned_identity(source, identity, "LLVM input")
        _assert_scanned_identity(plugin, plugin_identity, "LLVM plugin")
        report = {
            "ok": True, "format": "open-release-guard-native-obfuscation/v1",
            "object": str(output / "protected.o"), "report": str(output / "report.json"),
            "profile": profile, "seed": build_seed, "target_triple": triple,
            "toolchain_dir": str(tools), "llvm_versions": versions,
            "plugin_sha256": _sha(plugin_data), "input_sha256": _sha(original),
            "before_ir_sha256": _sha(before_bytes), "after_ir_sha256": _sha(after_bytes),
            "object_sha256": _sha(artifact), "object_bytes": len(artifact), "pass_pipeline": pipeline,
            "requested": list(functions), "changed": [item["name"] for item in observations if item["changed"]],
            "functions": observations, "transformation_applied": True,
            "functional_evaluation": "not_performed", "recovery_evaluation": "not_performed",
        }
        if virtualized:
            report.update(experimental=True, generated_functions=sorted(set(after) - set(before)),
                          vm_configuration={"profile": "builtin-amice-simple-vmp", "runtime_scope": "module",
                                            "bytecode_scope": "func", "polymorph_scope": "func",
                                            "emit_markers": False, "dump_bytecode": False, "dump_lowering": False})
        if code_seal is not None:
            report.update(code_seal=code_seal, vm_coverage_stage="before_sealing",
                          sealed_ir_sha256=_sha(codegen_bytes),
                          sealed_files={name: {"path": str(output / name), "bytes": len(data), "sha256": _sha(data)}
                                        for name, data in additional_files.items()})
        with ExitStack() as rollback:
            output.mkdir(mode=0o700)
            rollback.callback(output.rmdir)
            outputs = {"protected.o": artifact, **additional_files,
                       "report.json": json.dumps(report, indent=2).encode("utf-8") + b"\n"}
            for name, data in outputs.items():
                path = output / name
                write_new(path, data)
                rollback.callback(path.unlink)
            rollback.pop_all()
    return report
