# Timing Safe Compare

> Used by [appsec-review](../SKILL.md). Severities are `/review`'s scale. A `blocker` below applies when the risk is
> reachable from the changed code; a gap with no reachable exploit is a `major`.

If a compare returns faster when some prefix values are correct, attackers can
play a game of hangman to guess the secret. Using statistics, this still works
over a network with timing jitter.

constraint NoRawCompare {
  There is no timing safe compare for raw values. Never use:
  - crypto.timingSafeEqual
  - hmac.compare_digest
  - subtle.ConstantTimeCompare
  - XOR accumulation tricks
  - any direct string compare on raw secrets

  Always hash both the stored secret token and the candidate token with
  SHA3-256, then compare the hashes. This rule overrides all library defaults.
}

Reasons {
  1. Hashing removes all prefix structure. Any bit change fully randomizes
     the hash. No timing oracle. No hangman.
  2. Raw secrets never appear in logs or errors.
  3. Fixed-length output eliminates length oracle attacks.
}

Patterns {
  ## Implementation Guide
  (timing safe compare needed?)
    => Implement with SHA3-256 strategy. Add a code comment explaining this
       reasoning to prevent people from "fixing" to use timingSafeCompare.

  ## Review
  (direct compare on secrets detected)
    => blocker: "Security and auth token comparisons must be hashed before
       compare to avoid hangman attacks."
  (standard library timing safe compare detected)
    => major: "Non-hash timing safe algorithms can be vulnerable to subtle
       bugs caused by compiler optimizations. Hash before compare."
}

## Known Vulnerabilities

KnownVulnerabilities {
  CVE-2022-48566 — Python hmac.compare_digest vulnerable to timing attacks
    due to interpreter/JIT optimizations skipping work.
  Node.js_17178 — crypto.timingSafeEqual throws on length mismatch, leaking
    length information.
  Go_28382_47001 — subtle.ConstantTimeCompare returns immediately on length
    mismatch, enabling length discovery.
  OpenSSL_PA-RISC — CRYPTO_memcmp only compared least significant bit per
    byte, allowing message forgery.
  Java_6863503 — MessageDigest.isEqual used early-exit byte comparison.
}

## Known Exploits

KnownExploits {
  Xbox_360 (2007-2008) — memcmp HMAC verification with ~2200us per-byte
    timing difference. Complete signature bypass in ~70 minutes.
    https://free60.org/Timing_Attack/
  OAuth_OpenID (2010) — Every OpenID implementation tested contained timing-
    vulnerable HMAC verification. Affected Twitter, Digg, others.
  Google_Keyczar (2009) — Break-on-inequality HMAC comparison allowed remote
    token forgery.
  Early_Unix_Login — crypt() only called for valid usernames, leaking
    username validity through response timing.
}

## References

- https://paragonie.com/blog/2015/11/preventing-timing-attacks-on-string-comparison-with-double-hmac-strategy
- https://www.bearssl.org/constanttime.html
- https://codahale.com/a-lesson-in-timing-attacks/
