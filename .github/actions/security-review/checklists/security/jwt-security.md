# JWT Security Review

> Used by [appsec-review](../SKILL.md). Severities are `/review`'s scale. A `blocker` below applies when the risk is
> reachable from the changed code; a gap with no reachable exploit is a `major`.

**AVOID JWT if you can.** Prefer opaque tokens with server-side sessions.

Patterns {
  ## Session State
  any(refresh token rotation, refresh reuse detection, jti denylist,
      jti revocation, token bound to session, token bound to device,
      logout invalidates token server-side)
    => blocker: Prefer opaque tokens with server-side sessions.
       You're tracking state anyway.

  ## Storage & Transport
  (token in localStorage or sessionStorage)
    => blocker: XSS vulnerable. Use httpOnly Secure SameSite=Strict cookies.
  (token in URL or query params)
    => blocker: Leaks via logs, Referer, browser history, analytics.
  (token logged or sent to analytics)
    => blocker: Scrub tokens from all logging pipelines.
  (SameSite=None or missing CSRF protection)
    => blocker: CSRF exposure. Use SameSite=Strict or add CSRF tokens.

  ## Algorithm & Signature
  (JWT 'none' algorithm) => blocker: Signature bypass. Reject unsigned tokens.
  (JWT verification disabled) => blocker: Always verify signatures.
  (jwt.decode without verify) => blocker: Use jwt.verify().
  (alg from token used to select verification)
    => blocker: Alg confusion. Strict allowlist + key type must match algorithm.
  (HS256 or symmetric algorithm)
    => blocker: Use asymmetric algorithms (RS256/ES256).

  ## Verification Failure Handling
  (verification failure allows anonymous access)
    => blocker: Fail closed. Invalid token = no access.
  (verification failure allows partial or degraded access)
    => blocker: Fail closed. Invalid token = no access.

  ## Token Purpose
  (ID token used as access token)
    => blocker: Wrong token type. Use access tokens (typ: at+jwt) for API auth.
  (typ header not validated)
    => blocker: Reject tokens without expected typ. Prevents token confusion.

  ## Key Handling
  (kid used to fetch key from untrusted source)
    => blocker: SSRF/key injection. Allowlist kid values.
  (JWKS URL derived from iss without strict allowlist)
    => blocker: Attacker-controlled keys. Pin JWKS URLs.
  (JWKS endpoint not pinned or cached)
    => major: Cache JWKS with TTL. Validate kid against known set.
  (multi-issuer: verification keys shared across issuers)
    => blocker: Issuer key isolation required. One keyset per issuer.

  ## Claims Validation
  (iss not validated) => blocker: Confused deputy. Verify issuer matches expected value.
  (aud not validated) => blocker: Token reuse across services. Verify audience.
  (exp not validated) => blocker: Always check exp claim.
  (nbf present and not validated) => blocker: Must validate. Reject on failure.
  (iat present and not validated) => blocker: Must validate. Reject on failure.
  (nbf and iat not checked when absent)
    => major: Consider requiring nbf/iat. Validate with <=60s clock skew.

  ## Authorization
  (roles or scopes trusted without server check)
    => blocker: Claims are assertions, not policy. Server must enforce.

  ## Cookie Hardening
  (cookie missing __Host- prefix)
    => major: Use __Host- to enforce Secure, Path=/, no Domain.
  (cookie Domain set to parent domain)
    => major: Subdomain hijacking. Omit Domain or use __Host-.

  ## Lifetime
  (access token lifetime >= 1 day) => blocker: Max 15 min for stateless JWT.
  (access token lifetime > 15 min and < 1 day)
    => major: Shorter is better. 15 min max recommended.
}
