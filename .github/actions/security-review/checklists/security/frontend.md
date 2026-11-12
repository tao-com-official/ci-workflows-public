# Frontend security checklist

Client code: React web and React Native apps.

- **Secrets** — none in the bundle, logs, or analytics payloads. Anything shipped to the client is public.
- **Non-custodial wallets** — the app never requests, reads, stores, or logs private keys, seed phrases, or raw seeds.
  Signing belongs in the user's wallet.
- **Token and key storage** — web: session tokens in `httpOnly` `Secure` `SameSite` cookies, not `localStorage` or
  `sessionStorage`. Mobile: keys, seed phrases, passwords, and session tokens in secure storage (Keychain / Keystore,
  e.g. `expo-secure-store`) — never AsyncStorage, unencrypted MMKV, or module globals. The cookie advice in the JWT
  reference does not apply on mobile.
- **Biometric and auth gates** fail closed.
- **Input** — user and remote input (amounts, addresses, deep-link parameters) is validated with a schema before any
  signing or network call. Addresses are validated for the chain they are used on.
- **Rendering** — no unsanitised HTML (`dangerouslySetInnerHTML`, `WebView` with remote HTML), no navigation to an
  untrusted URL.
- **Transactions** — the submitted amount, recipient, token, and chain match what the user confirmed, and a network
  switch cannot bypass the signing checks. Check approval scope and spender; investigate unexpected spenders and
  undisclosed unlimited approvals. Wrong decimals or floating-point balance arithmetic can cause irreversible loss — a demonstrated
  risk is a `blocker`.

- **Edge functions and proxies** the app ships (serverless functions, RPC proxies) are server code: secrets bound
  from the environment, authorisation and session validation, CORS scoped to the app's origins, and an allowlist of
  upstreams — never an open proxy. Read the [backend checklist](backend.md) for them.

Do not re-platform authentication during a review. Then read [JWT security](jwt-security.md) (its storage and transport rules) for authentication or session changes.
Server-side verification rules in it apply to the API, not the client.
