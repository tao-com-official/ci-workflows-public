#!/usr/bin/env python3
"""The `security-scans / semgrep` verdict: block on ERROR findings and on the always-block rules, warn on the rest.

usage: semgrep-cutoff.py <semgrep --json-output file> <always-block list>

A finding blocks when its rule's severity is ERROR (or HIGH or CRITICAL, Semgrep's newer names), or
when its rule is on the always-block list whatever its severity. WARNING, INFO, LOW and MEDIUM
findings are listed in the job summary and as warnings. A severity this script doesn't know blocks.
env: GITHUB_STEP_SUMMARY (optional).
"""
import json
import os
import sys

WARN_ONLY = {'WARNING', 'INFO', 'LOW', 'MEDIUM'}


def read_list(path):
    with open(path, encoding='utf-8') as f:
        return {line.strip() for line in f if line.strip() and not line.startswith('#')}


def judge(results, always_block):
    """[(blocks, why, finding)] for Semgrep's `results`."""
    out = []
    for r in results:
        sev = str((r.get('extra') or {}).get('severity') or '').upper()
        if r.get('check_id') in always_block:
            out.append((True, 'always blocks', r))
        elif sev in WARN_ONLY:
            out.append((False, sev, r))
        else:
            out.append((True, sev or 'no severity', r))
    return out


def esc(s, prop=False):
    s = str(s).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    return s.replace(':', '%3A').replace(',', '%2C') if prop else s


def cell(s):
    return str(s).replace('|', '\\|').replace('\n', ' ').strip()


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError) as err:
        print(f'::error title=semgrep::No readable Semgrep results ({err}). See the Scan step.')
        return 1
    rows = judge(data.get('results') or [], read_list(argv[2]))
    blocking = [r for r in rows if r[0]]
    for blocks, why, r in rows:
        start = (r.get('start') or {}).get('line', 1)
        msg = ' '.join(str((r.get('extra') or {}).get('message') or '').split())[:600]
        kind = 'error' if blocks else 'warning'
        print(f"::{kind} file={esc(r.get('path', ''), True)},line={start},title={esc(r.get('check_id'), True)}::{esc(f'[{why}] {msg}')}")
    summary = ['### Semgrep', '']
    if rows:
        summary += [f'{len(blocking)} blocking, {len(rows) - len(blocking)} warning only. ERROR findings and the always-block rules block; WARNING and INFO are listed here.', '',
                    '| Verdict | Rule | Severity | Where |', '| --- | --- | --- | --- |']
        for blocks, why, r in sorted(rows, key=lambda x: not x[0]):
            sev = (r.get('extra') or {}).get('severity') or ''
            where = f"{r.get('path', '')}:{(r.get('start') or {}).get('line', '')}"
            summary.append(f"| {'blocks' if blocks else 'warns'}{' (always-block rule)' if why == 'always blocks' else ''} | `{cell(r.get('check_id'))}` | {cell(sev)} | `{cell(where)}` |")
    else:
        summary.append('No findings.')
    errors = data.get('errors') or []
    if errors:
        summary += ['', f'Semgrep reported {len(errors)} error(s) (files it could not parse are skipped, as before); see the Scan step.']
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as f:
            f.write('\n'.join(summary) + '\n')
    print(f'Semgrep: {len(blocking)} blocking finding(s), {len(rows) - len(blocking)} warning(s).')
    return 1 if blocking else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
