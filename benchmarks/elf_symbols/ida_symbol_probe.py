"""Query two function starts in a fresh IDA Freeware 5.0 database (Windows)."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def loaded_prefix(image, address):
    if image[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("expected a little-endian 32-bit ELF")
    phoff, = struct.unpack_from("<I", image, 28)
    entsize, count = struct.unpack_from("<HH", image, 42)
    for i in range(count):
        kind, offset, va, _, size = struct.unpack_from("<5I", image, phoff + i * entsize)
        if kind == 1 and va <= address and address + 8 <= va + size:
            start = offset + address - va
            return image[start:start + 8].hex()
    raise ValueError("expected eight file-backed bytes at the given address")


IDC = """
#include <idc.idc>
static inspect(f, ea) {
  auto limit, cursor, n, i;
  if (GetFunctionAttr(ea, FUNCATTR_START) != ea || !isCode(GetFlags(ea)))
    Exit(11);
  limit = GetFunctionAttr(ea, FUNCATTR_END);
  n = 0;
  for (cursor = ea; cursor != BADADDR && cursor < limit; cursor = NextHead(cursor, limit))
    if (isCode(GetFlags(cursor)) && GetMnem(cursor) != "") n++;
  if (n == 0) Exit(12);
  fprintf(f, "%08X\\n%s\\n%d\\n", ea, GetFunctionName(ea), n);
  for (i = 0; i < 8; i++) fprintf(f, "%02X", Byte(ea+i));
  fprintf(f, "\\n");
}
static main() {
  auto f, gate;
  Wait();
  gate = LocByName("rg_public_entry");
  if (gate == BADADDR || gate != PUBLIC_ADDRESS) Exit(14);
  f = fopen(GetInputFilePath()+".probe", "w");
  if (f == 0) Exit(13);
  inspect(f, PRIVATE_ADDRESS);
  inspect(f, gate);
  fclose(f);
  Exit(0);
}
"""


def windows_for_pid(pid):
    """Inspect this IDA process only. Return visible forms and short control labels."""
    import ctypes
    from ctypes import wintypes

    user = ctypes.WinDLL("user32", use_last_error=True)
    callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.EnumWindows.argtypes = [callback, wintypes.LPARAM]
    user.EnumChildWindows.argtypes = [wintypes.HWND, callback, wintypes.LPARAM]
    forms = []

    def describe(hwnd):
        name = ctypes.create_unicode_buffer(120)
        cls = ctypes.create_unicode_buffer(80)
        user.GetWindowTextW(hwnd, name, len(name))
        user.GetClassNameW(hwnd, cls, len(cls))
        return {"class": cls.value, "caption": " ".join(name.value.split())}

    @callback
    def top(hwnd, _):
        owner = wintypes.DWORD()
        user.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != pid or not user.IsWindowVisible(hwnd):
            return True
        info = describe(hwnd)
        info["controls"] = []

        @callback
        def child(handle, _):
            if user.IsWindowVisible(handle) and len(info["controls"]) < 32:
                info["controls"].append(describe(handle))
            return True

        user.EnumChildWindows(hwnd, child, 0)
        forms.append(info)
        return True

    user.EnumWindows(top, 0)
    return forms


def run_ida(cmd, work):
    with subprocess.Popen(cmd, cwd=work) as proc:
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            print("IDA startup windows:", windows_for_pid(proc.pid), flush=True)
            try:
                proc.wait(timeout=75)
            except subprocess.TimeoutExpired as exc:
                forms = windows_for_pid(proc.pid)
                proc.kill()
                proc.wait(timeout=10)
                log = work / "ida.log"
                detail = log.read_text(errors="replace")[-2000:] if log.is_file() else "no log"
                raise RuntimeError(f"IDA timed out; windows={forms!r}, log={detail}") from exc
        return proc.returncode


def main():
    binary, report, private, public = sys.argv[1:]
    addresses = (int(private, 0), int(public, 0))
    image = Path(binary).read_bytes()
    prefixes = [loaded_prefix(image, addr) for addr in addresses]
    ida = Path(os.environ["RG_IDA_BIN"]).resolve(strict=True)
    expected = {
        ida: "2c8f2b69ba1cfd8b3c99c5fc5041b7feb7c4ff8baf442e9e3bf5e0a085405c02",
        ida.with_name("ida.wll"): "2aaa4a19a703bb65df57ca9f3521a178089068c388916626f1d49c1a2a0ca466",
    }
    for path, digest in expected.items():
        if sha256(path.read_bytes()) != digest:
            raise ValueError(f"unexpected IDA Freeware 5.0 component: {path.name}")
    result = {"tool": "IDA", "version": "5.0.0.879 Freeware", "input_sha256": sha256(image)}
    with tempfile.TemporaryDirectory(prefix="ida-symbol-") as tmp:
        work = Path(tmp)
        sample = work / "sample.elf"
        sample.write_bytes(image)
        probe = IDC.replace("PRIVATE_ADDRESS", hex(addresses[0])).replace("PUBLIC_ADDRESS", hex(addresses[1]))
        (work / "probe.idc").write_text(probe, encoding="ascii")
        cmd = [str(ida), "-A", "-c", f"-L{work / 'ida.log'}", f"-S{work / 'probe.idc'}", "sample.elf"]
        status = run_ida(cmd, work)
        output = work / "sample.elf.probe"
        if status or not output.is_file():
            log = work / "ida.log"
            detail = log.read_text(errors="replace")[-2500:] if log.exists() else "no log"
            raise RuntimeError(f"IDA did not finish the probe (exit {status}): {detail}")
        fields = output.read_text(encoding="ascii").splitlines()
        if len(fields) != 8 or sample.read_bytes() != image:
            raise RuntimeError("unexpected IDA output or modified input")
        for i, key in enumerate(("private", "public")):
            entry, name, count, prefix = fields[4*i:4*i+4]
            if int(entry, 16) != addresses[i] or not name or int(count) < 1 or prefix.lower() != prefixes[i]:
                raise RuntimeError(f"IDA database and {key} function bytes did not agree")
            result[key + "_entry"] = hex(int(entry, 16))
            result[key + "_name"] = name
            result[key + "_instructions"] = int(count)
            result[key + "_prefix_hex"] = prefix.lower()
    with Path(report).open("x", encoding="utf-8") as output_file:
        json.dump(result, output_file, indent=2)
        output_file.write("\n")


if __name__ == "__main__":
    main()
