from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

HEAD = '0bb99e389f2936947c218fb07e5b8fa65c97084b'
PARENT = 'a2e7d6a03d300474d27a2c5f54b5a2db2d35d2aa'
PRODUCTION = 'packages/sdk-typescript/src/daemon/sse.ts'
TEST = 'packages/sdk-typescript/test/unit/sse-frame-scanning.test.ts'
COMPATIBILITY = 'packages/sdk-typescript/test/unit/daemon-sse.test.ts'
BLOBS = {
    PRODUCTION: 'e3bf74dccc97f483b1d442c1fdbed15c94003e90',
    TEST: 'fd58448a4311fdf64b4d597fec5b45fbc52a6810',
    COMPATIBILITY: 'a4e44c19bab587c51df43c013689398c80f574fb',
}
MUTANT_BLOB = '8f1c7dd2f4f780e0482da141bf5eb698972297c3'
TARGET = 'preserves every frame in a large batch (' + json.dumps('\r\n\r\n') + ')'


def git_blob(content: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()


def run(command: list[str], cwd: Path, check: bool = True, env: dict | None = None):
    print('COMMAND', json.dumps(command), 'CWD', str(cwd), flush=True)
    return subprocess.run(command, cwd=cwd, check=check, timeout=900, env=env)


def main() -> None:
    root = Path.cwd()
    controller = Path(__file__).resolve().parent
    package = root / 'packages/sdk-typescript'
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == HEAD
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD^'], text=True).strip() == PARENT
    assert subprocess.check_output(['git', 'diff', '--name-only', PARENT, HEAD], text=True).splitlines() == [TEST]
    originals = {path: (root / path).read_bytes() for path in BLOBS}
    assert {path: git_blob(raw) for path, raw in originals.items()} == BLOBS
    assert subprocess.check_output(['git', 'show', f'{PARENT}:{PRODUCTION}']) == originals[PRODUCTION]
    assert subprocess.check_output(['git', 'show', f'{PARENT}:{COMPATIBILITY}']) == originals[COMPATIBILITY]
    mutant = (controller / 'qwen-sse-quadratic-mutant.ts').read_bytes()
    assert git_blob(mutant) == MUTANT_BLOB
    print('SOURCE_IDENTITY', json.dumps({'head': HEAD, 'parent': PARENT, 'blobs': BLOBS, 'only_changed_file': TEST, 'production_unchanged': True, 'mutant_blob': MUTANT_BLOB}), flush=True)
    run(['corepack', 'pnpm', 'exec', 'eslint', TEST], root)
    run(['corepack', 'pnpm', 'exec', 'prettier', '--check', TEST], root)
    stages = []

    def test(stage: str, negative: bool) -> None:
        report = Path(os.environ['RUNNER_TEMP']) / f'sse-scan-{stage}.json'
        error_report = report.with_suffix('.unhandled.json')
        report.unlink(missing_ok=True)
        error_report.unlink(missing_ok=True)
        reporter = controller / 'qwen-unhandled-errors-reporter.mjs'
        assert reporter.exists()
        stage_env = dict(os.environ, QWEN_VALIDATION_ERROR_REPORT=str(error_report))
        script = 'test:ci' if stage == 'candidate' else 'test'
        result = run(['npm', 'run', script, '--', 'test/unit/sse-frame-scanning.test.ts', 'test/unit/daemon-sse.test.ts', '--retry=0', '--reporter=json', f'--reporter={reporter}', f'--outputFile={report}'], package, check=False, env=stage_env)
        assert report.exists() and error_report.exists(), f'Missing native report in {stage}'
        unhandled = json.loads(error_report.read_text())
        assert unhandled['count'] == 0 and unhandled['errors'] == [], unhandled
        data = json.loads(report.read_text())
        cases = [case for suite in data['testResults'] for case in suite['assertionResults']]
        failed = [case for case in cases if case['status'] == 'failed']
        passed = [case for case in cases if case['status'] == 'passed']
        expected_failures = [TARGET] if negative else []
        assert data['numTotalTests'] == len(cases) == 23
        assert len(passed) + len(failed) == 23
        assert sorted(case['title'] for case in failed) == expected_failures, [case['fullName'] for case in failed]
        assert data['numFailedTests'] == len(expected_failures)
        assert data['numPassedTests'] == 23 - len(expected_failures)
        assert result.returncode == int(negative), (stage, result.returncode)
        assert data['success'] == (not negative)
        if negative:
            assert 'to be less than 500' in '\n'.join(failed[0]['failureMessages']), failed[0]['failureMessages']
        evidence = {
            'stage': stage, 'head': HEAD, 'tests': len(cases), 'passed': len(passed), 'failed': len(failed),
            'skipped': 0, 'unhandled_errors': 0, 'exit_code': result.returncode,
            'failed_titles': [case['title'] for case in failed], 'failed_names': [case['fullName'] for case in failed],
            'failed_messages': [case.get('failureMessages', []) for case in failed],
            'report_sha256': hashlib.sha256(report.read_bytes()).hexdigest(),
            'unhandled_receipt_sha256': hashlib.sha256(error_report.read_bytes()).hexdigest(),
        }
        print('SSE_NATIVE_STAGE_RESULT', json.dumps(evidence), flush=True)
        stages.append(evidence)

    test('candidate', False)
    try:
        (root / PRODUCTION).write_bytes(mutant)
        assert (root / TEST).read_bytes() == originals[TEST]
        assert (root / COMPATIBILITY).read_bytes() == originals[COMPATIBILITY]
        test('quadratic-mutant', True)
    finally:
        (root / PRODUCTION).write_bytes(originals[PRODUCTION])
    assert all((root / path).read_bytes() == raw for path, raw in originals.items())
    test('restored-candidate', False)
    run(['git', 'diff', '--exit-code'], root)
    print('SSE_NATIVE_VALIDATION_COMPLETE', json.dumps({'head': HEAD, 'stages': stages, 'production_and_tests_restored': True, 'mutation_scope': 'Semantics-preserving quadratic scan; not the parent implementation', 'scope_limit': 'Known 16000-frame cost guard, not a universal proof of linear complexity'}), flush=True)


if __name__ == '__main__':
    main()
