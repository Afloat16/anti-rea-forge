from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

PARENT = '5fc5a98ecc08d2e89f29cbea57934928224977b5'
CONFIG = {
    'acpeof': {
        'head': 'bd430227b627dd2d6262fcea0e3954ddca10c77c',
        'package': 'packages/sdk-typescript',
        'files': ['test/unit/AcpHttpTransport.test.ts'],
        'production': ['packages/sdk-typescript/src/daemon/AcpHttpTransport.ts'],
        'tests': ['packages/sdk-typescript/test/unit/AcpHttpTransport.test.ts'],
        'total': 55,
        'failures': [
            'rejects a connection request on EOF and reopens for a later request',
            'keeps a session request alive when the connection stream closes',
        ],
    },
    'stdinerror': {
        'head': '32abd8c88bf2e4fb3891395dc7d2f3a279c1c360',
        'package': 'packages/sdk-typescript',
        'files': ['test/unit/ProcessTransport.test.ts'],
        'production': ['packages/sdk-typescript/src/transport/ProcessTransport.ts'],
        'tests': ['packages/sdk-typescript/test/unit/ProcessTransport.test.ts'],
        'total': 93,
        'failures': [
            'preserves an asynchronous stdin error through child exit (0, null)',
            'preserves an asynchronous stdin error through child exit (1, null)',
            'preserves an asynchronous stdin error through child exit (null, SIGTERM)',
            'consumes late stdin errors after intentional close without replacing the outcome',
            'consumes late stdin errors after intentional abort without replacing the outcome',
        ],
    },
    'imagequeue': {
        'head': 'd2b32dc99d798792d04f46fcffd98338913f737d',
        'package': 'packages/web-shell',
        'files': ['utils/imageIngestion.test.ts', 'hooks/use-composer-core-image-cancellation.dom.test.tsx'],
        'production': ['packages/web-shell/client/utils/imageIngestion.ts', 'packages/web-shell/client/hooks/useComposerCore.ts'],
        'tests': ['packages/web-shell/client/utils/imageIngestion.test.ts', 'packages/web-shell/client/hooks/use-composer-core-image-cancellation.dom.test.tsx'],
        'total': 60,
        'failures': [
            'does not start readers for an already cancelled batch',
            'stops starting queued readers when the batch becomes stale',
            'does not start queued image reads after clear',
            'does not start queued image reads after unmount',
            'accepts a new image batch after cancelling the previous batch',
        ],
    },
}

def run(command: list[str], *, cwd: Path, check: bool = True, timeout: int = 1200, env: dict | None = None):
    print('COMMAND', json.dumps(command), 'CWD', str(cwd), flush=True)
    return subprocess.run(command, cwd=cwd, check=check, timeout=timeout, env=env)

def main() -> None:
    key = sys.argv[1]
    config = CONFIG[key]
    root = Path.cwd()
    package = root / config['package']
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == config['head']
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD^'], text=True).strip() == PARENT
    changed = subprocess.check_output(['git', 'diff', '--name-only', PARENT, 'HEAD'], text=True).splitlines()
    assert sorted(changed) == sorted(config['production'] + config['tests']), changed
    originals = {path: (root / path).read_bytes() for path in changed}
    parents = {path: subprocess.check_output(['git', 'show', f'{PARENT}:{path}']) for path in config['production']}
    print('SOURCE_IDENTITY', json.dumps({'key':key,'head':config['head'],'parent':PARENT,'files':{p:hashlib.sha256(raw).hexdigest() for p,raw in originals.items()}}), flush=True)
    run(['corepack', 'pnpm', 'exec', 'eslint', *changed], cwd=root)
    run(['corepack', 'pnpm', 'exec', 'prettier', '--check', *changed], cwd=root)
    stages = []

    def test(stage: str, expected_failures: list[str]) -> None:
        report = Path(os.environ['RUNNER_TEMP']) / f'{key}-{stage}.json'
        error_report = report.with_suffix('.unhandled.json')
        report.unlink(missing_ok=True)
        error_report.unlink(missing_ok=True)
        reporter = Path(__file__).resolve().with_name('qwen-unhandled-errors-reporter.mjs')
        assert reporter.exists()
        stage_env = dict(os.environ, QWEN_VALIDATION_ERROR_REPORT=str(error_report))
        script = 'test:ci' if stage == 'candidate' else 'test'
        command = ['npm', 'run', script, '--', *config['files'], '--retry=0', '--reporter=json', f'--reporter={reporter}', f'--outputFile={report}']
        outcome = run(command, cwd=package, check=False, env=stage_env)
        assert report.exists(), f'No native Vitest JSON for {stage}'
        assert error_report.exists(), f'No native unhandled-error receipt for {stage}'
        unhandled = json.loads(error_report.read_text())
        assert unhandled['count'] == 0 and unhandled['errors'] == [], unhandled
        data = json.loads(report.read_text())
        cases = [case for suite in data['testResults'] for case in suite['assertionResults']]
        failed = [case for case in cases if case['status'] == 'failed']
        passed = [case for case in cases if case['status'] == 'passed']
        assert data['numTotalTests'] == len(cases) == config['total'], (stage, data['numTotalTests'], len(cases))
        assert len(passed) + len(failed) == len(cases), f'Skipped or unexecuted cases in {stage}'
        assert sorted(case['title'] for case in failed) == sorted(expected_failures), [case['fullName'] for case in failed]
        assert data['numFailedTests'] == len(expected_failures)
        assert data['numPassedTests'] == config['total'] - len(expected_failures)
        assert outcome.returncode == (1 if expected_failures else 0), (stage, outcome.returncode)
        assert data['success'] == (not expected_failures), (stage, data['success'])
        evidence = {'key':key,'stage':stage,'head':config['head'],'tests':len(cases),'passed':len(passed),'failed':len(failed),'skipped':0,'unhandled_errors':0,'exit_code':outcome.returncode,'failed_names':[case['fullName'] for case in failed],'failed_messages':[case.get('failureMessages',[]) for case in failed],'report_sha256':hashlib.sha256(report.read_bytes()).hexdigest(),'unhandled_receipt_sha256':hashlib.sha256(error_report.read_bytes()).hexdigest()}
        print('NATIVE_STAGE_RESULT', json.dumps(evidence), flush=True)
        stages.append(evidence)

    test('candidate', [])
    try:
        for path, raw in parents.items():
            (root / path).write_bytes(raw)
        assert all((root / path).read_bytes() == originals[path] for path in config['tests'])
        test('parent-production', config['failures'])
    finally:
        for path in config['production']:
            (root / path).write_bytes(originals[path])
    assert all((root / path).read_bytes() == raw for path, raw in originals.items())
    test('restored-candidate', [])
    run(['git', 'diff', '--exit-code'], cwd=root)
    print('NATIVE_VALIDATION_COMPLETE', json.dumps({'key':key,'head':config['head'],'parent':PARENT,'stages':stages,'production_and_tests_restored':True}), flush=True)

if __name__ == '__main__':
    main()
