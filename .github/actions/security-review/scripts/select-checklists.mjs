#!/usr/bin/env node
// Which of the copied checklists don't apply to this diff, so the reviewer isn't handed (and doesn't
// spend turns reading) references it has no use for. The vendored files stay verbatim; only whole
// files are left out, and only on a clear signal. When unsure, a checklist stays.
//
//   node select-checklists.mjs <checklist dir> <pr-diff.txt> <server globs, newline-separated>
//   (deletes the ones that don't apply from <checklist dir> and prints their names, comma-separated)
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { changedFiles, matchesAny } from './lib.mjs';

// Each conditional checklist and the signal that keeps it. The rest always stay.
const RULES = {
  // Only when the diff touches server code. With no server_paths configured nobody can tell, so it stays.
  'backend.md': ({ files, serverGlobs }) => !serverGlobs.length || files.some((f) => matchesAny(f, serverGlobs)),
  // Auth, sessions or tokens anywhere in the diff.
  'jwt-security.md': ({ diff }) => /jw[tsk]|jose|session|cookie|bearer|token|oauth|oidc|log[-_ ]?in|log[-_ ]?out|sign[-_ ]?in|auth|credential/i.test(diff),
  // Anything that could compare a secret, token, key or nonce.
  'timing-safe-compare.md': ({ diff }) => /secret|token|api[-_]?key|nonce|hmac|digest|signature|password|passphrase|otp|compare/i.test(diff),
};

export function leftOut({ names, diff, serverGlobs }) {
  const files = changedFiles(diff);
  return names.filter((n) => RULES[n] && !RULES[n]({ diff, files, serverGlobs }));
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [dir, diffPath, serverText] = process.argv.slice(2);
  const serverGlobs = (serverText ?? '').split('\n').map((s) => s.trim()).filter(Boolean);
  const names = Object.keys(RULES).filter((n) => existsSync(join(dir, n)));
  const out = leftOut({ names, diff: readFileSync(diffPath, 'utf8'), serverGlobs });
  for (const n of out) rmSync(join(dir, n));
  process.stdout.write(out.join(', '));
}
