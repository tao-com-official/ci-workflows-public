#!/usr/bin/env node
// Picks the code review's mode from the path tier and the risk classifier's verdict for the head SHA
// (Phase 1.2):
//   skip  Low risk: every path Low and the classifier agrees (floor low, tier low, no person needed,
//         the whole diff seen). No AI review at all; the security review passes Low the same way.
//   full  Everything else, Medium and High alike: the code review, then the separate security review.
//
//   node review-mode.mjs <tier> <risk.json or "">   (prints the mode)
import { existsSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function chooseMode({ tier, verdict }) {
  // A verdict on a cut diff (`partial`) saw only part of the change, so it can't lower anything.
  if (tier !== 'Low' || !verdict || verdict.needs_person !== false || verdict.partial === true) return 'full';
  return verdict.floor === 'low' && verdict.tier === 'low' ? 'skip' : 'full';
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [tier, verdictPath] = process.argv.slice(2);
  let verdict = null;
  try {
    if (verdictPath && existsSync(verdictPath)) verdict = JSON.parse(readFileSync(verdictPath, 'utf8'));
  } catch {
    verdict = null;
  }
  process.stdout.write(chooseMode({ tier, verdict }));
}
