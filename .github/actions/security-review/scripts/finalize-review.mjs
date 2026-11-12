#!/usr/bin/env node
// Checks what the reviewer wrote and builds the review payload and the meta artifact. The workflow,
// not the model, owns the marker, the round, coverage and the cap, so the gate can trust them.
//
//   node finalize-review.mjs '<json: {marker, round, round_cap, commit_id, truncated, skipped, prefix}>'
//
// Reads <prefix>-body.md, <prefix>-comments.json, <prefix>-meta.json; writes <prefix>.json (the POST
// body), <prefix>-meta.json (normalised) and <prefix>-fixed.json (an array). Exits 1 when there is
// no body. The prefix is `review` (the default) for the code review and `security` for the security
// review, whose summary line reads `N security findings, M hardening` or `No security findings.`.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const MAX_BODY = 65_000;

export function finalize(ctx, files) {
  const { marker, round, round_cap: roundCap, commit_id: commitId, truncated, skipped = [], tier } = ctx;
  if (!files.body?.trim()) return { error: 'the review body is missing or empty' };
  const parse = (text, fallback) => {
    try {
      return JSON.parse(text);
    } catch {
      return fallback;
    }
  };
  let comments = parse(files.comments ?? '[]', []);
  if (!Array.isArray(comments)) comments = [];
  comments = comments
    .filter((c) => typeof c?.path === 'string' && Number.isInteger(c?.line) && typeof c?.body === 'string')
    .map((c) => ({ path: c.path, line: c.line, side: 'RIGHT', body: `${marker}\n${c.body}` }));

  let fixed = parse(files.fixed ?? '[]', []);
  fixed = Array.isArray(fixed) ? fixed.map(String).filter((id) => /^\d+$/.test(id)) : [];

  const modelMeta = parse(files.meta ?? '{}', {});
  const open = Array.isArray(modelMeta.open)
    ? modelMeta.open.filter((o) => o && typeof o.id === 'string').map((o) => ({ id: o.id, fingerprint: String(o.fingerprint ?? ''), tag: String(o.tag ?? '') }))
    : [];
  const headLine = files.body.split('\n')[0];
  // `N important, M nits` (code) or `N security findings, M hardening` (security).
  const counted = headLine.match(/^(\d+) (?:important|security findings?), (\d+) (?:nits?|hardening)/);
  const important = Math.max(
    comments.length,
    counted ? Number(counted[1]) : 0,
    Number.isInteger(modelMeta.important) ? modelMeta.important : 0,
    // Blocking IDs: I1… in the code review, S1… in the security review.
    open.filter((o) => /^[IS]\d+$/.test(o.id)).length,
  );

  let body = files.body;
  // Round cap: past it, Important findings that remain get "reconsider", not new inline threads.
  const cap = round > roundCap && important > 0;
  if (cap) {
    comments = [];
    const reconsider = `Round ${round}: ${important} important findings remain after ${roundCap} rounds. Step back and reconsider the approach before another fix round.`;
    if (!body.includes('Step back and reconsider')) body = `${reconsider}\n\n${body}`;
  }
  // Coverage is partial when the workflow cut or filtered the diff, whatever the model says.
  const coverage = truncated || modelMeta.coverage === 'partial' ? 'partial' : 'full';
  if (truncated && !/^#+\s*Coverage/im.test(body)) body += '\n\n## Coverage\n\nPartial: the diff was cut at 400 KB.';

  const meta = {
    reviewer: marker.match(/ai-review:([a-z-]+)/)?.[1] ?? 'code',
    commit_id: commitId,
    round,
    important,
    nits: Number.isInteger(modelMeta.nits) ? modelMeta.nits : counted ? Number(counted[2]) : 0,
    open,
    coverage,
    cap,
    skipped_paths: skipped,
    // The path-floor tier, so a run that reuses this meta can still report it.
    ...(tier ? { tier } : {}),
  };
  const hidden = `\n\n<!-- ai-review:meta ${JSON.stringify(meta).replace(/--/g, '\\u002d\\u002d')} -->`;
  let full = `${marker}\n${body.trim()}`;
  if (full.length + hidden.length > MAX_BODY) full = `${full.slice(0, MAX_BODY - hidden.length - 80)}\n\n_…review truncated (GitHub's length limit)._`;
  full += hidden;
  return { payload: { commit_id: commitId, event: 'COMMENT', body: full, comments }, meta, fixed };
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const ctx = JSON.parse(process.argv[2]);
  const prefix = ctx.prefix ?? 'review';
  if (!/^[a-z-]+$/.test(prefix)) {
    console.log(`::error::Bad prefix '${prefix}'.`);
    process.exit(1);
  }
  const read = (f) => (existsSync(f) ? readFileSync(f, 'utf8') : undefined);
  const out = finalize(ctx, {
    body: read(`${prefix}-body.md`),
    comments: read(`${prefix}-comments.json`),
    fixed: read(`${prefix}-fixed.json`),
    meta: read(`${prefix}-meta.json`),
  });
  if (out.error) {
    console.log(`::error::${out.error}`);
    process.exit(1);
  }
  writeFileSync(`${prefix}.json`, JSON.stringify(out.payload));
  writeFileSync(`${prefix}-meta.json`, JSON.stringify(out.meta, null, 2));
  writeFileSync(`${prefix}-fixed.json`, JSON.stringify(out.fixed));
  console.log(`round ${out.meta.round}: ${out.meta.important} important, ${out.meta.nits} nits, coverage ${out.meta.coverage}, cap ${out.meta.cap}`);
}
