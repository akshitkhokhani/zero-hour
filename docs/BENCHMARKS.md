# Benchmarks

Real numbers from `python3 bench/run.py <dir>` on 2026-10-22 (Python 3.10.10, darwin, Apple Silicon laptop).
Each repo is a shallow clone of the default branch at the commit shown. Every scan is live (OSV, GitHub Advisory DB, CISA KEV, EPSS, incident cards) with `--no-host`, so this machine doesn't skew results.

## Cost

| Repo | Commit | Packages | First run (cold cache) | Repeat run CPU | Peak memory | `--deep` CPU / memory |
|---|---|---:|---:|---:|---:|---:|
| BerriAI/litellm | `f2118fc` | 2779 | 14.9 s | 0.3 s | 48 MB | 4.0 s / 85 MB |
| WordPress/wordpress-develop | `e29e51d` | 4990 | 16.9 s | 0.2 s | 46 MB | 3.1 s / 53 MB |
| home-assistant/core | `eff77ac2` | 1313 | 6.4 s | 0.3 s | 38 MB | 3.8 s / 52 MB |
| langchain-ai/langchain | `b84fa61` | 2438 | 10.0 s | 0.3 s | 50 MB | 1.3 s / 58 MB |
| laravel/laravel | `9ffef3b` | 0 | 6.1 s | 0.1 s | 43 MB | 0.2 s / 36 MB |
| microsoft/vscode | `b81f5c08` | 3201 | 12.7 s | 0.2 s | 48 MB | 1.3 s / 54 MB |
| n8n-io/n8n | `1e66e5df` | 3986 | 15.2 s | 0.3 s | 42 MB | 2.2 s / 62 MB |
| supabase/supabase | `8b4be6cd` | 3556 | 18.2 s | 0.3 s | 46 MB | 4.1 s / 62 MB |
| tauri-apps/tauri | `ba1e205` | 2042 | 9.5 s | 0.1 s | 37 MB | 0.5 s / 41 MB |
| vercel/next.js | `443a9e7a` | 9411 | 43.1 s | 0.8 s | 61 MB | 1.8 s / 87 MB |

Max peak memory across all runs: **87 MB**. Max CPU time: **5.4 s**. First-run wall time is mostly network (live feeds). Repeat runs within an hour use the cache.

## Accuracy vs osv-scanner

Baseline: Google's [osv-scanner](https://github.com/google/osv-scanner) `scan source -r` on the same checkout. A finding is one (package, version, advisory) pair.

| Repo | osv-scanner findings | Same row | Reported as a live incident line | osv-scanner's guess from unpinned `requirements.txt` | Missed by zero-hour |
|---|---:|---:|---:|---:|---:|
| BerriAI/litellm | 129 | 83 | 2 | 44 | 0 |
| WordPress/wordpress-develop | 311 | 306 | 5 | 0 | 0 |
| home-assistant/core | 96 | 9 | 21 | 66 | 0 |
| langchain-ai/langchain | 39 | 20 | 19 | 0 | 0 |
| laravel/laravel | — | — | — | — | — (no package sources found) |
| microsoft/vscode | 74 | 70 | 4 | 0 | 0 |
| n8n-io/n8n | 168 | 161 | 7 | 0 | 0 |
| supabase/supabase | 313 | 267 | 45 | 0 | 1 |
| tauri-apps/tauri | 14 | 14 | 0 | 0 | 0 |
| vercel/next.js | 1253 | 1245 | 8 | 0 | 0 |
| **Total** | **2397** | **2175** | **111** | **110** | **1** |

On lockfile-backed findings, zero-hour reports **2286 of 2287 (99.96%)**.

How to read the columns:

- **Reported as a live incident line**: advisories published in the last 7 days. zero-hour lists these as incidents ("Pillow: 15 new high/critical advisories") instead of advisory rows.
- **Guess from unpinned requirements**: for a plain `requirements.txt`, osv-scanner resolves transitive dependencies itself and picks versions. zero-hour reports only versions that a lockfile or `==` pin proves. Add a lockfile (`uv lock`, `pip-compile`) to cover these.
- **Missed**: the remaining gaps. `bench/results.json` lists each one.

## What zero-hour found that a CVE scanner does not

- **BerriAI/litellm**:
  - LiteLLM 1.107.0 malicious release (PyPI + Docker) steals credentials via cook.pth
  - Pillow: 15 new high/critical advisories in the last 7 days (3 critical)
  - pillow: 4 new high/critical advisories in the last 7 days
  - … +3 more
- **WordPress/wordpress-develop**:
  - launch-editor: `fs.existsSync()` existence check can be bypassed on Windows
  - follow-redirects: 2 new high/critical advisories in the last 7 days
  - markdown-it: Quadratic complexity in smartquotes with unmatched closing quotes
- **home-assistant/core**:
  - Pillow: 15 new high/critical advisories in the last 7 days (3 critical)
  - pillow: 4 new high/critical advisories in the last 7 days
- **langchain-ai/langchain**:
  - Pillow: 15 new high/critical advisories in the last 7 days (3 critical)
  - pillow: 4 new high/critical advisories in the last 7 days
- **microsoft/vscode**:
  - markdown-it: Quadratic-time rendering of a single multi-line link reference definition wit
  - MCP TypeScript SDK: One HTTP request within the default size limit could exhaust server me
  - launch-editor: `fs.existsSync()` existence check can be bypassed on Windows
  - … +1 more
- **n8n-io/n8n**:
  - Storybook: Missing origin validation in Storybook preview allows code injection from malic
  - MCP TypeScript SDK: One HTTP request within the default size limit could exhaust server me
  - aiohttp: 3 new high/critical advisories in the last 7 days
  - … +2 more
- **supabase/supabase**:
  - Pillow: 18 new high/critical advisories in the last 7 days (3 critical)
  - pillow: 4 new high/critical advisories in the last 7 days
  - Sentry-Javascript: Middleware Bypass when using Tunnel route
  - … +6 more
- **tauri-apps/tauri**:
  - Microsoft Windows — Microsoft Windows Command Injection Vulnerability (CISA KEV, added 202
- **vercel/next.js**:
  - next: 2 new high/critical advisories in the last 7 days (1 critical)
  - Storybook: Missing origin validation in Storybook preview allows code injection from malic
  - MCP TypeScript SDK: One HTTP request within the default size limit could exhaust server me
  - … +1 more

## Reproduce

```bash
mkdir repos && cd repos
for r in BerriAI/litellm WordPress/wordpress-develop home-assistant/core langchain-ai/langchain laravel/laravel microsoft/vscode n8n-io/n8n supabase/supabase tauri-apps/tauri vercel/next.js; do
  git clone --depth 1 https://github.com/$r.git $(echo $r | tr / _)
done
cd .. && python3 bench/run.py repos && python3 bench/report.py
```
