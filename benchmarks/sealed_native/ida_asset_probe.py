"""Export initialized ELF32 bytes and a discovered gate from pinned IDA Freeware 5.0."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


from elf_bytes import MAX_BYTES, require, verify_loaded_bytes

ENGINE_HASHES = {
    "idag.exe": "2c8f2b69ba1cfd8b3c99c5fc5041b7feb7c4ff8baf442e9e3bf5e0a085405c02",
    "ida.wll": "2aaa4a19a703bb65df57ca9f3521a178089068c388916626f1d49c1a2a0ca466",
}

IDC = r'''
#include <idc.idc>
static main() {
  auto f, gate, stop, cursor, n, i, prefix, seg, end, begin, count, total, first;
  Wait();
  gate = LocByName("rg_asset_gate");
  if (gate == BADADDR || GetFunctionAttr(gate, FUNCATTR_START) != gate) Exit(11);
  stop = GetFunctionAttr(gate, FUNCATTR_END);
  if (stop <= gate || stop - gate < 6 || stop - gate > 65536) Exit(12);
  n = 0;
  for (cursor = gate; cursor != BADADDR && cursor < stop; cursor = NextHead(cursor, stop))
    if (isCode(GetFlags(cursor)) && GetMnem(cursor) != "") n++;
  if (n == 0) Exit(13);
  f = fopen(GetInputFilePath()+".probe", "w");
  if (f == 0) Exit(14);
  fprintf(f, "{\"gate_name\":\"rg_asset_gate\",\"gate_entry\":\"0x%08X\",", gate);
  fprintf(f, "\"gate_size\":%d,\"gate_instructions\":%d,\"gate_prefix_hex\":\"", stop-gate, n);
  prefix = stop-gate;
  if (prefix > 16) prefix = 16;
  for (i = 0; i < prefix; i++) fprintf(f, "%02X", Byte(gate+i));
  fprintf(f, "\",\"blocks\":[");
  first = 1;
  total = 0;
  for (seg = FirstSeg(); seg != BADADDR; seg = NextSeg(seg)) {
    end = SegEnd(seg);
    if (end <= seg || end-seg > 2097152) Exit(15);
    cursor = seg;
    while (cursor < end) {
      while (cursor < end && !isLoaded(cursor)) cursor++;
      begin = cursor;
      while (cursor < end && isLoaded(cursor)) cursor++;
      count = cursor-begin;
      if (count > 0) {
        total = total+count;
        if (total > 2097152) Exit(16);
        if (!first) fprintf(f, ",");
        first = 0;
        fprintf(f, "{\"start\":\"0x%08X\",\"size\":%d,\"hex\":\"", begin, count);
        for (i = begin; i < cursor; i++) fprintf(f, "%02X", Byte(i));
        fprintf(f, "\"}");
      }
    }
  }
  if (total == 0) Exit(17);
  fprintf(f, "],\"loaded_bytes\":%d}\n", total);
  fclose(f);
  Exit(0);
}
'''



def sha256(data):
    return hashlib.sha256(data).hexdigest()



def main():
    binary, report = map(Path, sys.argv[1:])
    image = binary.read_bytes()
    require(0 < len(image) <= MAX_BYTES and image[:7] == b"\x7fELF\x01\x01\x01",
            "Expected a bounded little-endian ELF32 for IDA 5.0")
    ida = Path(os.environ["RG_IDA_BIN"]).resolve(strict=True)
    for name, digest in ENGINE_HASHES.items():
        require(sha256(ida.with_name(name).read_bytes()) == digest, "Unexpected IDA engine component")
    require(ida.name.lower() == "idag.exe", "Expected the pinned IDA GUI")
    with tempfile.TemporaryDirectory(prefix="ida-asset-") as directory:
        work = Path(directory)
        sample = work / "sample.elf"
        sample.write_bytes(image)
        script = work / "probe.idc"
        script.write_text(IDC, encoding="ascii")
        cmd = [str(ida), "-A", "-c", f"-L{work / 'ida.log'}", f"-S{script}", "sample.elf"]
        env = {**os.environ, "IDA_NORELOC": "1", "IDA_ELF_PATCH_MODE": "0"}
        if os.environ.get("RG_IDA_CONFIRM_FREEWARE") == "1":
            from ida_first_run import run_ida
            status = run_ida(cmd, work, env=env)
        else:
            status = subprocess.run(cmd, cwd=work, env=env, timeout=180, check=False).returncode
        output = work / "sample.elf.probe"
        if status or not output.is_file():
            log = work / "ida.log"
            detail = log.read_text(errors="replace")[-2500:] if log.is_file() else "no log"
            raise RuntimeError(f"IDA did not finish its extraction (exit {status}): {detail}")
        record = json.loads(output.read_text(encoding="ascii"))
        require(sample.read_bytes() == image, "IDA input changed during analysis")
        verify_loaded_bytes(image, record)
    record.update(tool="IDA", version="5.0.0.879 Freeware", input_sha256=sha256(image),
                  loader_options={"IDA_NORELOC": "1", "IDA_ELF_PATCH_MODE": "0"})
    with report.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, separators=(",", ":"))
        stream.write("\n")


if __name__ == "__main__":
    main()
