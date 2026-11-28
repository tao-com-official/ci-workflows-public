#!/usr/bin/env python3
"""Builds security-scans' Semgrep rule snapshot from the two rule repos checked out at pinned commits.

usage: build-semgrep-rules.py <rule id list> <semgrep/semgrep-rules dir> <trailofbits/semgrep-rules dir> <out.json>

Each id is the registry's id, which is the rule file's path with dots plus the rule's own id
(`yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag`
is rule `github-actions-mutable-action-tag` in yaml/github-actions/security/github-actions-mutable-action-tag.yaml;
`trailofbits.` ids come from the trailofbits repo). The output keeps those ids, so `nosemgrep` comments
and `--exclude-rule` entries written against `--config auto` still match. Write the output to the
directory semgrep runs in: semgrep prefixes a rule's id with the config file's directory otherwise.
Fails when an id is missing from the checkouts, so a snapshot never silently loses a rule.
"""
import json
import os
import re
import sys

SEGMENT = re.compile(r'^[A-Za-z0-9_-]+$')


def load_yaml(path):
    with open(path, encoding='utf-8') as f:
        text = f.read()
    try:
        from ruamel.yaml import YAML  # in the Semgrep image
        return YAML(typ='safe', pure=True).load(text)
    except ImportError:
        pass
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        return json.loads(text)  # JSON is YAML: the unit tests' fixtures


def read_ids(path):
    with open(path, encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]


def locate(rule_id, roots):
    """(file, rule's own id) for a registry id, or (None, reason)."""
    parts = rule_id.split('.')
    if len(parts) < 2 or not all(SEGMENT.match(p) for p in parts):
        return None, 'not a rule id'
    root, segs = (roots['trailofbits'], parts[1:-1]) if parts[0] == 'trailofbits' else (roots['semgrep'], parts[:-1])
    if not segs:
        return None, 'not a rule id'
    # The registry lowercases the path in an id (X509-subject-name-validation.yaml is
    # ...cryptography.x509-subject-name-validation...), so each segment is matched ignoring case.
    path = root
    for i, seg in enumerate(segs):
        last = i == len(segs) - 1
        want = {seg.lower() + ext for ext in ('.yaml', '.yml')} if last else {seg.lower()}
        try:
            names = sorted(os.listdir(path))
        except OSError:
            names = []
        match = [n for n in names if n.lower() in want and (os.path.isfile if last else os.path.isdir)(os.path.join(path, n))]
        if len(match) != 1:
            return None, ('no rule file ' if not match else 'more than one rule file ') + '/'.join(segs) + '.yaml'
        path = os.path.join(path, match[0])
    return path, parts[-1]


def build(ids, roots):
    rules, missing, files = [], [], {}
    for rule_id in ids:
        path, own = locate(rule_id, roots)
        if path is None:
            missing.append(f'{rule_id}: {own}')
            continue
        if path not in files:
            files[path] = (load_yaml(path) or {}).get('rules') or []
        found = [r for r in files[path] if isinstance(r, dict) and r.get('id') == own]
        if len(found) != 1:
            missing.append(f'{rule_id}: {len(found)} rules called {own} in {path}')
            continue
        rules.append({**found[0], 'id': rule_id})
    return rules, missing


def main(argv):
    if len(argv) != 5:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    ids_file, semgrep_dir, tob_dir, out = argv[1:]
    ids = read_ids(ids_file)
    rules, missing = build(ids, {'semgrep': semgrep_dir, 'trailofbits': tob_dir})
    if missing:
        for m in missing:
            print(f'::error title=Semgrep rule snapshot::{m}')
        print(f'{len(missing)} of {len(ids)} rules not found at the pinned commits. Bump the list and the commits together (scripts/bump-semgrep-rules.sh).')
        return 1
    with open(out, 'w', encoding='utf-8') as f:
        json.dump({'rules': rules}, f, default=str)
    print(f'Semgrep rule snapshot: {len(rules)} rules.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
