"""Exercise the public release command and its refusal-to-publish exit code."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class SplitMapsCLI(unittest.TestCase):
    def test_hidden_build_and_inline_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            build = work / "build"
            build.mkdir()
            payload = b"console.log(42);\n"
            (build / "app.js").write_bytes(payload)
            source_map = {"version": 3, "file": "app.js", "sources": ["main.ts"],
                          "names": [], "mappings": "AAAA", "sourcesContent": ["console.log(42 as number);"]}
            map_bytes = json.dumps(source_map).encode("utf-8")
            (build / "app.js.map").write_bytes(map_bytes)

            def invoke(suffix):
                return subprocess.run([
                    sys.executable, "-m", "releaseguard", "split-source-maps", "--root", str(build),
                    "--public", str(work / ("public" + suffix)),
                    "--private", str(work / ("symbols" + suffix)),
                ], capture_output=True, text=True, timeout=30)

            result = invoke("1")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(json.loads(result.stdout)["ok"])
            self.assertEqual((work / "public1/app.js").read_bytes(), payload)
            self.assertFalse((work / "public1/app.js.map").exists())
            self.assertEqual((work / "symbols1/app.js.map").read_bytes(), map_bytes)
            self.assertEqual((build / "app.js.map").read_bytes(), map_bytes)
            (build / "app.js").write_bytes(payload + b"//# sourceMappingURL=data:application/json;base64,e30=\n")
            result = invoke("2")
            self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
            self.assertFalse(json.loads(result.stdout)["ok"])
            self.assertFalse((work / "public2").exists())
            self.assertFalse((work / "symbols2").exists())
