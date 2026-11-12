// LavaMoat policy diff: which packages gain a power (network, extension APIs, code execution, DOM,
// storage, workers…) between the base and the change. A package that can import another package
// gets that package's powers too, so powers are taken one import hop out (Fable red-team #8).

// Matched against dotted global paths (`chrome.storage.local.set`, `document.createElement`).
const POWER =
  /^(fetch|XMLHttpRequest|WebSocket|EventSource|WebTransport|RTCPeerConnection|BroadcastChannel|navigator\.sendBeacon|importScripts|eval|Function|postMessage|chrome|browser|localStorage|sessionStorage|indexedDB|caches|Worker|SharedWorker|navigator\.serviceWorker|serviceWorker|WebAssembly|crypto\.subtle|document\.cookie|navigator\.clipboard|window|self|globalThis|top|parent|frames|opener|open|document|navigator|location|Image|Blob|URL\.createObjectURL|process|require)(\.|$)/;
// Read-only lookups that are everywhere and grant nothing worth a review.
const BENIGN = /^(process\.env\.NODE_ENV|navigator\.userAgent|navigator\.language|navigator\.languages|location\.protocol|location\.hostname|location\.origin|location\.href|document\.documentElement|document\.body|self\.crypto|window\.crypto)$/;

export const isPower = (g) => POWER.test(g) && !BENIGN.test(g);

/** {resource: Set(power)} with own globals, builtins and native modules (and writes marked). */
function ownPowers(policy) {
  const out = {};
  for (const [name, r] of Object.entries(policy?.resources ?? {})) {
    const s = new Set();
    for (const [g, v] of Object.entries(r.globals ?? {})) {
      if (v === 'write') s.add(`${g} (write)`);
      else if (v && isPower(g)) s.add(g);
    }
    for (const [b, v] of Object.entries(r.builtin ?? {})) if (v) s.add(`builtin:${b}`);
    if (r.native) s.add('native');
    out[name] = s;
  }
  return out;
}

/** Merges the generated policy with its override (the override wins, as LavaMoat applies it). */
export function mergePolicies(...policies) {
  const out = { resources: {} };
  for (const p of policies) {
    for (const [name, r] of Object.entries(p?.resources ?? {})) {
      const cur = (out.resources[name] ??= {});
      for (const k of ['globals', 'packages', 'builtin']) if (r[k]) cur[k] = { ...(cur[k] ?? {}), ...r[k] };
      if (r.native !== undefined) cur.native = r.native;
    }
  }
  return out;
}

/** Own powers plus those of every package it may import directly (one hop). */
export function effectivePowers(policy) {
  const own = ownPowers(policy);
  const out = {};
  for (const [name, r] of Object.entries(policy?.resources ?? {})) {
    const s = new Map([...own[name]].map((p) => [p, null]));
    for (const [dep, v] of Object.entries(r.packages ?? {})) {
      if (!v) continue;
      for (const p of own[dep] ?? []) if (!s.has(p)) s.set(p, dep);
    }
    out[name] = s;
  }
  return out;
}

/** Findings for powers a resource has at head but not at base. */
export function policyFindings(file, base, head) {
  const b = effectivePowers(base);
  const h = effectivePowers(head);
  const out = [];
  for (const [name, powers] of Object.entries(h)) {
    const before = b[name] ?? new Map();
    const gained = [...powers].filter(([p]) => !before.has(p));
    if (!gained.length) continue;
    const list = gained.map(([p, via]) => (via ? `${p} (via ${via})` : p));
    out.push({
      rule: 'lavamoat-new-power',
      severity: 'block',
      file,
      message: `${b[name] ? '' : 'new resource '}\`${name}\` gains ${list.slice(0, 12).join(', ')}${list.length > 12 ? ` and ${list.length - 12} more` : ''}`,
    });
  }
  return out;
}
