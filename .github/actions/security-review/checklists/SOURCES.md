# Vendored checklists

Copied verbatim from `tao-com-official/agent-harness`. Repo rules (REVIEW.md, AGENTS.md, conventions)
win over these files; these files win over the core prompt's defaults. Change them only by re-vendoring
from a newer harness SHA, and run the eval on that PR.

| File here | Upstream path | Upstream SHA |
|---|---|---|
| security/backend.md | skills/core/appsec-review/references/backend.md | 89eb464216bb0fa8bcfb66db078609d603de6be5 |
| security/frontend.md | skills/core/appsec-review/references/frontend.md | 89eb464216bb0fa8bcfb66db078609d603de6be5 |
| security/jwt-security.md | skills/core/appsec-review/references/jwt-security.md | 89eb464216bb0fa8bcfb66db078609d603de6be5 |
| security/owasp-2025.md | skills/core/appsec-review/references/owasp-2025.md | 89eb464216bb0fa8bcfb66db078609d603de6be5 |
| security/timing-safe-compare.md | skills/core/appsec-review/references/timing-safe-compare.md | 89eb464216bb0fa8bcfb66db078609d603de6be5 |

Files in `checklists/` are copied for every reviewer; files in `checklists/<reviewer>/` only for that
reviewer, so the security references reach only the security review. The repo's own
`.github/security-review.md` (base branch) wins over them, for example where a wallet app holds keys.
