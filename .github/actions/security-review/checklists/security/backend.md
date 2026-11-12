# Backend security checklist

Server code: HTTP and GraphQL handlers, queue consumers, jobs, data access, outbound clients.

- **Authorisation** — every endpoint or resolver that returns user-scoped data checks the caller's identity and
  ownership on the server. Deny by default. Claims in a token are assertions, not policy.
- **Injection** — user-supplied values reach SQL, ClickHouse, NoSQL, shell commands, and templates only as bound
  parameters. Never interpolate them into a query or command string.
- **External data** — responses from third-party APIs and messages from queues are parsed with a schema before use.
- **Secrets and personal data** — tokens, API keys, credentials, and PII never appear in logs, error messages, error
  extensions, or responses. Errors returned to clients carry no stack trace or internal detail.
- **Caching** — a response that depends on the caller is never cached in a shared or public cache.
- **Outbound requests** — no request to a URL a user controls without an allowlist (SSRF).
- **CORS** — scoped to the origins that need it; never a wildcard on an endpoint that uses credentials.
- **Abuse** — expensive or enumerable endpoints have a limit (rate, page size, query depth or complexity for GraphQL).

Then read [JWT security](jwt-security.md) for authentication or session changes, and
[timing-safe compare](timing-safe-compare.md) when the code compares a secret, token, API key, or nonce.
