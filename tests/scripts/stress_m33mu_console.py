#!/usr/bin/env python3
"""Temporary hosted stress gate. Uses the real lifecycle step and assertions."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / '.github/workflows/m33mu.yml').read_text()
START = WORKFLOW.index('          echo "Guest vector tables (SP, reset PC):"')
END = WORKFLOW.index('\n  # Label-selected', START)
LIFECYCLE = textwrap.dedent(WORKFLOW[START:END])
FIXED = LIFECYCLE[LIFECYCLE.index('log="$RUNNER_TEMP/wolfboot-wolftrust-m33mu.log"'):]
OLD = (ROOT / 'tests/scripts/m33mu_console_main_checks.sh').read_text()
RUNNER = (ROOT / 'tests/target/run_m33mu_scenario.sh').read_text()
LOCAL = RUNNER[RUNNER.index('guest0_log="$repo/ci-m33mu-'):]


def shell(code, env):
    return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', code],
                          cwd=ROOT, env=env, capture_output=True)


def validate(raw, directory, env, negatives=False):
    log = directory / 'wolfboot-wolftrust-m33mu.log'
    log.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    fixed = shell(FIXED, env)
    old = shell(OLD, env)
    (directory / 'fixed-checks.txt').write_bytes(fixed.stdout + fixed.stderr)
    (directory / 'main-checks.txt').write_bytes(old.stdout + old.stderr)
    if fixed.returncode:
        raise RuntimeError('fixed CI assertions failed: ' + fixed.stderr.decode(errors='replace'))
    local_env = dict(env, repo=str(ROOT), scenario='positive', family='positive', log=str(log))
    local = shell(LOCAL, local_env)
    (directory / 'local-checks.txt').write_bytes(local.stdout + local.stderr)
    if local.returncode:
        raise RuntimeError('local positive assertions failed: ' + local.stdout.decode(errors='replace'))
    if hashlib.sha256(log.read_bytes()).hexdigest() != digest:
        raise RuntimeError('assertion processing changed the raw evidence')
    if negatives:
        marker = re.compile(rb'psa_hash_compute\(SHA-256\) KAT verified')
        damaged, count = marker.subn(b'psa_hash_compute(SHA-256) KAT verifie', raw)
        if not count:
            raise RuntimeError('cannot apply missing-byte negative control')
        cases = {'missing-byte': damaged, 'fault': raw + b'\n[HARDFLT]\n',
                 'missing-guest1': raw.replace(b'freertos_guest1: psa hash ok',
                                                b'freertos_guest1: hash FAILED')}
        for name, data in cases.items():
            log.write_bytes(data)
            negative_env = dict(env, WT_TEST_GUEST='freertos')
            result = shell(FIXED, negative_env)
            (directory / (name + '-checks.txt')).write_bytes(result.stdout + result.stderr)
            if result.returncode == 0:
                raise RuntimeError('negative control incorrectly accepted: ' + name)
        log.write_bytes(raw)
    return dict(fixed_status=0, main_status=old.returncode, raw_sha256=digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=50)
    parser.add_argument('--replay', type=Path)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 100:
        parser.error('iterations must be between 1 and 100')
    if args.replay:
        raw = args.replay.read_bytes()
        measurement = re.search(rb'token measurement=([0-9a-f]{64})', raw).group(1).decode()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            env = dict(os.environ, RUNNER_TEMP=tmp, WT_TEST_GUEST='freertos',
                       WT_EXPECTED_MEASUREMENT_HEX=measurement, WT_ENGINE='hsm')
            print(json.dumps(validate(raw, directory, env, negatives=True)))
        return
    output = Path(os.environ['RUNNER_TEMP']) / 'console-stress'
    output.mkdir(parents=True, exist_ok=True)
    results = []
    # Only these task-owned child processes are stopped in finally.
    workers = [subprocess.Popen(['python3', '-c', 'while True: pass']) for _ in range(2)]
    try:
        for iteration in range(1, args.iterations + 1):
            directory = output / f'{iteration:03d}'
            directory.mkdir()
            env = dict(os.environ, RUNNER_TEMP=str(directory))
            seed = 0x0E497B6E if iteration % 5 == 1 else 0x0E497B6E + iteration
            code = LIFECYCLE.replace('--timeout 60;', f'--timeout 60 --rng-seed {seed:#x};')
            if code == LIFECYCLE:
                raise RuntimeError('the canonical emulator invocation changed')
            result = shell(code, env)
            (directory / 'lifecycle.txt').write_bytes(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError(f'iteration {iteration} failed without retry (exit {result.returncode})')
            raw = (directory / 'wolfboot-wolftrust-m33mu.log').read_bytes()
            record = dict(iteration=iteration, seed=seed,
                          **validate(raw, directory, env, negatives=iteration == 1))
            results.append(record)
            (output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
            print(json.dumps(record), flush=True)
        old_failures = sum(r['main_status'] != 0 for r in results)
        summary = f'{len(results)}/{args.iterations} fixed passes; main parser fails {old_failures} on identical logs'
        print(summary, flush=True)
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as stream:
            stream.write(summary + '\n')
    finally:
        for worker in workers:
            worker.terminate()
        for worker in workers:
            worker.wait()


if __name__ == '__main__':
    main()
