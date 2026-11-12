# OWASP Top 10:2025

> Used by [appsec-review](../SKILL.md). Severities are `/review`'s scale. A `blocker` below applies when the risk is
> reachable from the changed code; a gap with no reachable exploit is a `major`.

When reviewing code, explicitly check for each category below.
Full details: https://owasp.org/Top10/2025/

OWASPChecklist {
  A01_BrokenAccessControl {
    https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
    Includes SSRF.
    Check for: missing authorization checks, IDOR, CORS misconfiguration,
    path traversal, privilege escalation, SSRF via user-supplied URLs,
    URL/parameter tampering, JWT/cookie/hidden field manipulation,
    unprotected API methods (POST, PUT, DELETE), forced browsing to
    restricted pages, session ID reuse after logout.
    Enforce: deny by default, least privilege, server-side access control,
    centralized access control mechanisms, record ownership in data models,
    rate limiting on APIs, session invalidation on logout.
  }

  A02_SecurityMisconfiguration {
    https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/
    Check for: default credentials, unnecessary features/ports enabled,
    verbose error messages leaking stack traces, missing security headers,
    permissive CORS, sample/test apps left in production, debug code active
    in production, directory listing enabled, hardcoded secrets in config,
    weak SSL/TLS on cookies.
    Enforce: repeatable hardening process, minimal install, security headers,
    automated configuration verification, identity federation with short-lived
    credentials over static embedded secrets.
  }

  A03_SoftwareSupplyChainFailures {
    https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/
    Check for: unvetted dependencies, untracked transitive dependency versions,
    missing SBOM, no vulnerability scanning, unsigned packages, lack of lockfile
    integrity checks, single individuals able to deploy to production without
    review, unhardened CI/CD pipelines.
    Enforce: continuous vulnerability monitoring, components from trusted sources
    only with signed packages, separation of duties for production deployment,
    staged rollouts, documented change tracking for repos/build tools/registries,
    subscribe to security bulletins for all components.
  }

  A04_CryptographicFailures {
    https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/
    Check for: sensitive data in plaintext, weak algorithms (MD5, SHA1, DES,
    ECB mode), hardcoded keys/secrets, keys in repos, missing key rotation,
    missing encryption at rest/transit, weak RNG, IV reuse, passwords used as
    crypto keys, missing certificate validation, caching of sensitive responses,
    unencrypted protocols (FTP, STARTTLS).
    Enforce: classify sensitive data, TLS 1.2+ with forward secrecy, keys in
    HSM, authenticated encryption, adaptive password hashing (Argon2, scrypt,
    PBKDF2-HMAC-SHA-512), cryptographically random key generation, disable
    caching for sensitive responses.
  }

  A05_Injection {
    https://owasp.org/Top10/2025/A05_2025-Injection/
    Check for: SQL injection, XSS, command injection, NoSQL injection,
    LDAP injection, ORM injection, Expression Language injection, template
    injection, header injection, log injection, string concatenation in
    queries or commands, unvalidated user input from params/headers/cookies.
    Enforce: parameterized APIs (avoid interpreter directly), positive
    server-side input validation, escape special characters per interpreter,
    SAST/DAST/IAST in CI/CD, CSP headers, avoid eval/exec with user input.
    Note: parameterized stored procedures are still vulnerable if they use
    EXECUTE IMMEDIATE or exec() internally.
  }

  A06_InsecureDesign {
    https://owasp.org/Top10/2025/A06_2025-Insecure_Design/
    Design flaws cannot be fixed by perfect implementation.
    Check for: missing threat modeling, business logic flaws, lack of rate
    limiting, missing abuse case handling, trust boundary violations,
    unrestricted file uploads, improper privilege management, missing tenant
    segregation, unvalidated state change assumptions.
    Enforce: secure development lifecycle with AppSec early, threat modeling
    for critical flows (auth, authz, business logic), secure design pattern
    libraries, unit tests validating resistance to identified threats.
  }

  A07_AuthenticationFailures {
    https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/
    Check for: credential stuffing/password spray vulnerability, weak/default
    passwords permitted, missing MFA, plain text or weakly hashed password
    storage, knowledge-based recovery questions, session IDs exposed in URLs,
    session IDs reused after login, missing session invalidation on logout,
    default credentials in deployments.
    Enforce: MFA, check passwords against breached credential lists, NIST
    800-63b password policies (no forced rotation absent breach), high-entropy
    random session IDs generated server-side post-login, use standardized
    auth systems not custom implementations. See also jwt-security reference.
  }

  A08_SoftwareOrDataIntegrityFailures {
    https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/
    Check for: untrusted dependencies without integrity validation, unsigned
    updates/auto-updates, unverified CI/CD pipelines, missing code review for
    pipeline changes, insecure deserialization of untrusted data, missing
    digital signatures on software/data, unsigned firmware.
    Enforce: digital signatures to verify source and detect tampering, trusted
    package repos (internal vetting for high-risk), mandatory code/config
    review, CI/CD segregation and access controls, reject unsigned/unencrypted
    serialized data.
  }

  A09_SecurityLoggingAndAlertingFailures {
    https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/
    Check for: missing audit logs for logins/failed logins/high-value
    transactions, no alerting on suspicious activity, logs without sufficient
    context, sensitive data in logs (tokens, passwords, PII), missing log
    tamper protection, log injection via unencoded data, delayed attack
    detection.
    Enforce: append-only audit trails, proper log encoding to prevent injection,
    effective monitoring use cases with SOC response, honeytokens, incident
    response framework (NIST 800-61r2), fail closed, scrub sensitive data.
  }

  A10_MishandlingOfExceptionalConditions {
    https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/
    Check for: unhandled exceptions leaking stack traces, catch-all blocks
    that swallow errors silently, error messages exposing system internals,
    failing open instead of closed, unchecked return values, NULL pointer
    dereference, resource exhaustion from missing cleanup after exceptions,
    partial rollbacks in multi-step operations, missing error boundaries.
    Enforce: catch errors at the place they occur, handle meaningfully,
    roll back entire transactions on failure (fail closed), centralized error
    handling and logging, rate limiting and resource quotas, strict input
    validation, log deduplication to prevent flooding.
  }
}
