# ci-workflows-public

Security-only reusable workflows for tao.com's public repositories, **generated** from the private
`tao-com-official/ci-workflows` by `scripts/export-public.sh`. Don't edit files here: changes come
in as export pull requests, and a drift check in ci-workflows fails when this repo falls behind.

| Workflow | Checks | Exported from |
| --- | --- | --- |
| `.github/workflows/security-review.yml` | `security-review / review` | `security-review-v0.3.6` |
| `.github/workflows/security-scans.yml` | `security-scans / gitleaks`, `security-scans / semgrep`, `security-scans / osv`, `security-scans / funds-safety`, `security-scans / dependencies` | `security-scans-v0.2.2` |

Call them pinned to a full commit SHA. Public callers pass `standalone: true` to the security
review, which reads the calling repo's `.github/security-review.md` from its base branch.
`EXPORT.json` records the source commits and a SHA-256 of every exported file.
