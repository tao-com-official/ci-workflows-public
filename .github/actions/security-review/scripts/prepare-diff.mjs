#!/usr/bin/env node
// Turns the raw PR diff into what the reviewer reads, and works out the path tier.
//
//   node prepare-diff.mjs <full.diff> <risk.yml or ""> <skip globs, newline-separated> <since.diff> <round> <since_from_round>
//
// Writes since-filtered.diff (<since.diff> with the same files dropped) and pr-diff.txt (skip_paths dropped, then lockfiles and baselines (DEFAULT_DROP), cut at
// 400 KB; from <since_from_round> on, only the changes since the last review: the round cap for the
// code review, round 2 for the security review), and prints JSON: {tier, effort, truncated, skipped,
// dropped, scoped_to_since}. The tier is worked out before DEFAULT_DROP, so it never falls with it.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { DEFAULT_DROP, changedFiles, filterDiff, parseRiskYml, pathTier } from './lib.mjs';

const LIMIT = 400_000;
const [fullPath, riskPath, skipText, sincePath, roundArg, capArg] = process.argv.slice(2);
const round = Number(roundArg);
const cap = Number(capArg);
const skipGlobs = (skipText ?? '').split('\n').map((s) => s.trim()).filter(Boolean);

const { diff: kept, skipped } = filterDiff(readFileSync(fullPath, 'utf8'), skipGlobs);
const tiers = riskPath && existsSync(riskPath) ? parseRiskYml(readFileSync(riskPath, 'utf8')) : { high: [], medium: [], low: [] };
const tier = pathTier(changedFiles(kept), tiers);
const { diff, skipped: dropped } = filterDiff(kept, DEFAULT_DROP);

// From since_from_round on, the prompt gets only what changed since the last review.
const since = sincePath && existsSync(sincePath) ? filterDiff(filterDiff(readFileSync(sincePath, 'utf8'), skipGlobs).diff, DEFAULT_DROP).diff : '';
const scopedToSince = round >= cap && since.trim() !== '';
writeFileSync('since-filtered.diff', since);
const text = scopedToSince ? since : diff;
const buf = Buffer.from(text);
writeFileSync('pr-diff.txt', buf.subarray(0, LIMIT));

process.stdout.write(
  JSON.stringify({
    tier,
    effort: tier === 'Low' ? 'medium' : 'high',
    truncated: buf.length > LIMIT,
    skipped,
    dropped,
    scoped_to_since: scopedToSince,
  }),
);
