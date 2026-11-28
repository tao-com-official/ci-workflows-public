// The `security-scans / osv` verdict on a PR or in the merge queue (decision of 19 Nov 2026).
// Reads the advisories the change introduces, as osv-reporter's JSON output writes them (its own
// base-vs-head diff, unchanged), and judges each advisory group:
//   block  malicious package (MAL-)            always
//   block  CVSS 9.0 or higher (Critical)       fix or no fix
//   block  CVSS 7.0 or higher (High)           when a fixed version exists
//   warn   High with no fixed version, and everything under 7.0
//   block  no CVSS score and no GitHub severity label: it can't be judged, so it isn't let through
// The score is osv-scanner's own max_severity for the group; without one, the GitHub advisory label
// stands in (CRITICAL 9.0, HIGH 7.0, MODERATE 4.0, LOW 0.1). "A fixed version exists" means an
// affected range for the package ends in a `fixed` event. Groups osv-scanner's call analysis marks
// as never called pass, as osv-reporter's own --fail-on-vuln does.
//
// usage: node osv-cutoff.mjs <osv-reporter json>    env: GITHUB_STEP_SUMMARY (optional)
import { appendFileSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const CRITICAL = 9.0;
export const HIGH = 7.0;
const LABEL_SCORE = { CRITICAL: 9.0, HIGH: 7.0, MODERATE: 4.0, MEDIUM: 4.0, LOW: 0.1 };

const norm = (eco, name) => (/^pypi$/i.test(eco) ? name.toLowerCase().replace(/[-_.]+/g, '-') : name);

/** True when an affected range for this package has a `fixed` event. */
export function hasFix(vuln, pkg) {
  const affected = vuln?.affected ?? [];
  const mine = affected.filter(
    (a) =>
      a?.package?.name !== undefined &&
      norm(pkg.ecosystem ?? '', a.package.name) === norm(pkg.ecosystem ?? '', pkg.name ?? '') &&
      String(a.package.ecosystem ?? '').split(':')[0] === String(pkg.ecosystem ?? '').split(':')[0],
  );
  // No entry names the package (a renamed or aliased one): judge by every entry, which can only block more.
  return (mine.length ? mine : affected).some((a) => (a.ranges ?? []).some((r) => (r.events ?? []).some((e) => e.fixed)));
}

/** The group's score: osv-scanner's max_severity, else the highest GitHub label, else null. */
export function scoreOf(group, vulns) {
  const s = Number.parseFloat(group.max_severity);
  if (Number.isFinite(s)) return { score: s, from: 'CVSS' };
  const labels = vulns.map((v) => LABEL_SCORE[String(v?.database_specific?.severity ?? '').toUpperCase()]).filter((x) => x !== undefined);
  return labels.length ? { score: Math.max(...labels), from: 'label' } : { score: null, from: 'none' };
}

const called = (group) => {
  const a = Object.values(group.experimental_analysis ?? {});
  return a.length === 0 || a.some((x) => x?.called);
};

/** One row per advisory group the change introduces: { pkg, ids, score, from, fix, blocks, why, source }. */
export function judge(results) {
  const rows = [];
  for (const src of results?.results ?? []) {
    for (const p of src.packages ?? []) {
      const pkg = p.package ?? {};
      const byId = new Map((p.vulnerabilities ?? []).map((v) => [v.id, v]));
      const groups = p.groups?.length ? p.groups : [...byId.keys()].map((id) => ({ ids: [id], max_severity: '' }));
      for (const g of groups) {
        const ids = g.ids ?? [];
        const vulns = ids.map((id) => byId.get(id)).filter(Boolean);
        const { score, from } = scoreOf(g, vulns);
        const fix = vulns.some((v) => hasFix(v, pkg));
        const row = { pkg, ids, score, from, fix, source: src.source?.path ?? '' };
        if (ids.some((id) => id.startsWith('MAL-'))) Object.assign(row, { blocks: true, why: 'malicious package' });
        else if (!called(g)) Object.assign(row, { blocks: false, why: 'never called (osv-scanner call analysis)' });
        else if (score === null) Object.assign(row, { blocks: true, why: 'no severity to judge it by' });
        else if (score >= CRITICAL) Object.assign(row, { blocks: true, why: `Critical (${score})${fix ? '' : ', no fix yet'}` });
        else if (score >= HIGH && fix) Object.assign(row, { blocks: true, why: `High (${score}), fix available` });
        else if (score >= HIGH) Object.assign(row, { blocks: false, why: `High (${score}), no fixed version yet` });
        else Object.assign(row, { blocks: false, why: `under 7.0 (${score})` });
        rows.push(row);
      }
    }
  }
  return rows;
}

const esc = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const cell = (s) => String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function main(file) {
  let data;
  try {
    data = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    console.log(`::error title=osv::No readable osv-reporter output (${err.message}). See 'Report new advisories'.`);
    return 1;
  }
  const rows = judge(data);
  const blocking = rows.filter((r) => r.blocks);
  for (const r of rows) {
    const name = `${r.pkg.ecosystem ?? ''} ${r.pkg.name ?? ''}@${r.pkg.version ?? ''}`.trim();
    console.log(`::${r.blocks ? 'error' : 'warning'} title=${esc(`OSV ${r.ids.join(', ')}`).replace(/[:,]/g, ' ')}::${esc(`${name}: ${r.blocks ? 'blocks' : 'warns'}, ${r.why}. ${r.source}`)}`);
  }
  let md = '### OSV\n\n';
  if (rows.length) {
    md += `${blocking.length} blocking, ${rows.length - blocking.length} warning only, of the advisories this change introduces. `;
    md += 'Blocks: Critical (CVSS 9.0+) always, High (7.0+) when a fixed version exists, malicious packages, and anything without a severity.\n\n';
    md += '| Verdict | Package | Advisories | Score | Fixed version | Why | Lockfile |\n| --- | --- | --- | --- | --- | --- | --- |\n';
    for (const r of [...rows].sort((a, b) => Number(b.blocks) - Number(a.blocks) || (b.score ?? 99) - (a.score ?? 99))) {
      md += `| ${r.blocks ? 'blocks' : 'warns'} | \`${cell(`${r.pkg.name}@${r.pkg.version}`)}\` (${cell(r.pkg.ecosystem ?? '')}) | ${cell(r.ids.join(', '))} | ${r.score ?? 'none'}${r.from === 'label' ? ' (label)' : ''} | ${r.fix ? 'yes' : 'no'} | ${cell(r.why)} | \`${cell(r.source)}\` |\n`;
    }
  } else {
    md += 'This change introduces no advisories.\n';
  }
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
  console.log(`OSV: ${blocking.length} blocking advisory group(s), ${rows.length - blocking.length} warning(s).`);
  return blocking.length ? 1 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  if (process.argv.length !== 3) {
    console.error('usage: node osv-cutoff.mjs <osv-reporter json>');
    process.exitCode = 2;
  } else process.exitCode = main(process.argv[2]);
}
