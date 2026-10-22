# Deep check: CI/CD (GitHub Actions)

Load on `--deep`, or when an incident involves Actions, tokens, or a release pipeline.
All checks are read-only (`grep` on `.github/workflows/`, `gh api` GETs).

## Top risks and how to spot them
| # | Risk | Spot it | Safe pattern |
|---|---|---|---|
| 1 | `pull_request_target` + checkout of PR head ("pwn request"): fork code runs with secrets + write token | `grep -rn "pull_request_target" .github/workflows` then look for `ref: ${{ github.event.pull_request.head.sha }}` / `head.ref` / `github.head_ref` in `actions/checkout` | Use `pull_request`; if you need `_target`, never check out or run PR code in that job |
| 2 | Script injection via `${{ github.event.* }}` in `run:` | `grep -rnE '\$\{\{ *github\.(event\.(issue|pull_request|comment|review|review_comment|head_commit|commits|discussion|pages)|head_ref)' .github/workflows` | Pass through `env:` and quote: `env: TITLE: ${{ github.event.issue.title }}` → `run: echo "$TITLE"` |
| 3 | Unpinned third-party actions (tags/branches can be moved) | `grep -rnE 'uses: *[^./ ][^@ ]*@' .github/workflows \| grep -vE '@[0-9a-f]{40}'` | Pin by full commit SHA + version comment: `uses: actions/checkout@<40-char-sha> # v4.x.y`; let Dependabot/Renovate bump |
| 4 | Over-broad token permissions | no top-level `permissions:` key, or `write-all`; `gh api repos/<o>/<r>/actions/permissions/workflow` → `default_workflow_permissions` | Top-level `permissions: contents: read`, grant writes per job |
| 5 | Secrets reachable from forks | `pull_request_target` or `workflow_run` jobs that use `secrets.*`; artifacts from PR runs consumed by privileged jobs | Keep secrets out of fork-triggered jobs; treat downloaded PR artifacts as untrusted |
| 6 | Self-hosted runners on public repos | `grep -rn "runs-on:.*self-hosted" .github/workflows` | GitHub-hosted or ephemeral, isolated runners only; never persistent runners for public PRs |
| 7 | Long-lived cloud keys in secrets | `gh secret list`; names like `AWS_ACCESS_KEY_ID` | OIDC federation (`id-token: write` + cloud role) |
| 8 | Release/publish without provenance | publish jobs using `NPM_TOKEN`/`PYPI_TOKEN` | Trusted publishing (OIDC) + `npm publish --provenance` / PyPI attestations |
| 9 | Caches shared across trust boundaries | `actions/cache` restored in privileged jobs from PR-written keys | Separate cache keys for PR vs release jobs |
| 10 | Untrusted input to `GITHUB_ENV` / `GITHUB_OUTPUT` | `grep -rn 'GITHUB_ENV' .github/workflows` with event data | Validate/sanitize before writing |

## Useful read-only commands
```bash
ls .github/workflows/
gh api repos/<owner>/<repo>/actions/permissions                # allowed actions policy
gh api repos/<owner>/<repo>/actions/permissions/workflow       # default token permissions
gh secret list --repo <owner>/<repo>                           # names only, never values
gh api repos/<owner>/<repo>/branches/<default>/protection 2>/dev/null
```
If installed, these give deeper results: `zizmor .github/workflows`, `actionlint`,
`scorecard --repo=github.com/<owner>/<repo>` (OpenSSF Scorecard).

## Standards mapping
| Finding | OpenSSF Scorecard check | SLSA / SSDF |
|---|---|---|
| pwn request, script injection | Dangerous-Workflow | SSDF PS.1 (protect code), PW.1 |
| unpinned actions/images | Pinned-Dependencies | SLSA Build (hermetic, pinned inputs), SSDF PW.4 |
| broad token permissions | Token-Permissions | SSDF PO.5 (secure environments) |
| no branch protection / review | Branch-Protection, Code-Review | SSDF PS.1 |
| unsigned releases, no provenance | Signed-Releases | SLSA Build L2+ (signed provenance), SSDF PS.2 |
| self-hosted shared runners | — | SLSA Build L3 (isolated builds) |
| known-vulnerable deps | Vulnerabilities, Dependency-Update-Tool | SSDF RV.1 |

## Fix order
1. If a secret may already be exposed (pwn request ran, malicious action used): treat as a
   compromise. Check the card for dead-man switches, then rotate the secret and audit its use.
2. Remove the dangerous trigger/injection.
3. Pin actions by SHA and set least-privilege `permissions:`.
4. Move to OIDC / trusted publishing.
Under `--fix`, only edit workflow files locally (one approval per change); never push.
