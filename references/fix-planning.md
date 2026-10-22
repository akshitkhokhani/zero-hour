# Fix planning: evidence → safe, tailored plan

Load this after the verdict. The plan is **reasoned by you** from three inputs, not copied from
a card: (1) verdict evidence (what is installed where, what IOCs matched, which config is set),
(2) incident facts (card / live research: safe versions, mitigations, ordering dangers),
(3) the user's setup (package manager, OS, deployment, CI, who else is affected).

## 1. Classify each finding (drives which steps apply)
| State | Evidence | Plan needs |
|---|---|---|
| COMPROMISED | IOC `level: compromised` matched, or a malicious version was installed/run | contain → rotate → rebuild → hunt → harden |
| AFFECTED / EXPOSED | vulnerable or malicious version present, preconditions not mitigated, no IOC | (mitigate) → upgrade/pin → verify → hunt if exploited in the wild |
| MITIGATED | vulnerable but preconditions mitigated (e.g. flag off) | upgrade on normal schedule; keep the mitigation |
| UNKNOWN | could not check (image not pulled, no logs, no access) | the exact command that would resolve it |

**Reachability** decides the urgency, not whether to fix:
- Install hooks / start-up hooks (`.pth`, `preinstall`, `folderOpen` tasks) run without being
  imported → installed = executed. Treat as reachable.
- Library CVE: is the vulnerable function/feature used? `grep` imports/call sites; dev-only or
  test-only deps are lower urgency but still fixed.
- Runtime/server CVE: is it internet-facing, which SAPI/mode, which config? Pre-auth + exposed = top.
- Ranking: compromised > exploited-in-the-wild + reachable > KEV/high EPSS > severity.

## 2. Order (NIST SP 800-61) and hard constraints
1. **Contain / disarm**: stop processes, unload persistence, isolate. Any dead-man switch,
   token watcher or start-up re-trigger is handled here first.
2. **Rotate secrets** that the host/CI could read, from a clean machine, after step 1 is verified.
3. **Upgrade / pin** to the safe version by hash or digest; rebuild envs/images rather than patching in place.
4. **Verify** where the code actually runs (container, server worker, CI), then re-scan.
5. **Hunt for spread**: other machines, CI runners, repos, published packages, cloud audit logs.
6. **Harden** so it cannot recur (ignore-scripts, hash/digest pins, cooldowns, least privilege).
Carry every card/source `danger` into the plan as a `⚠` line **before** the step it guards.
Example: a worm that wipes `~` when its stolen token is revoked → "⚠ do not revoke until the
watcher is removed and confirmed gone" sits above the rotation step.

## 3. Tailor commands to what you detected
| Detected | Use |
|---|---|
| npm / pnpm / yarn / bun | that tool's pin + lockfile command (`npm install x@v --save-exact`, `pnpm add x@v`, `yarn add x@v`, `bun add x@v`); `overrides` / `pnpm.overrides` / `resolutions` for transitive deps |
| pip / uv / poetry / pipenv | `uv add 'x==v'` / `poetry add x==v` / `pipenv install x==v` / requirements pin + `--require-hashes`; constraints for transitive deps |
| composer | `composer require vendor/x:v` / `composer update vendor/x --with-dependencies` |
| Docker / compose / k8s | bump the tag, then pin `image@sha256:...`; `docker compose build --pull`; restart the workload |
| OS package / runtime | distro package manager + the distro's security tracker (backports keep old version strings) |
| macOS / Linux / Windows | `launchctl` / `systemctl --user` / Task Scheduler + PowerShell; give only the user's OS |
| CI (GitHub Actions) | workflow edits, runner rebuild, secret rotation in repo/org settings |
Use real paths from the evidence (`file:line`, actual site-packages dir, actual service name).
Use placeholders like `<PID>` only where the value must be confirmed first.

## 4. What you may do vs. only instruct
- **You may apply** (with `--fix`, one explicit user approval per step, showing the exact diff
  or command first): version pins, lockfile updates, `.npmrc`/`pip.conf` hardening, ini/config
  flags in the repo, pinning Actions by SHA, `permissions:` blocks, adding hashes/digests.
  These are local, reversible, and visible in `git diff`.
- **Never do yourself** (give copy-paste instructions instead): revoking/rotating credentials,
  deleting files, venvs, containers or cloud resources, killing processes, unloading services,
  `git push`, publishing packages, changing cloud/GitHub settings. Read-only inspection commands
  (`ls`, `launchctl print`, `systemctl status`, `npm ls`) may be run to gather evidence.
- Quarantine (`mv` to `~/zh-quarantine/`) beats `rm` in instructions: reversible, keeps forensics.

## 5. Output shape
```
1. ⚠ <danger, if any>
   <Step title>: why (one line)
   $ <command for THIS setup>
   ✓ verify: <command + expected result>
```
Keep it short: only steps that apply to this user's state and setup. Mark steps you applied
vs steps the user must run. End with the re-scan:
```bash
python3 scripts/zerohour.py <same args as before>    # expect the finding to turn green
```
If it is still red or UNKNOWN, say why and what to check next. Never claim fixed without a re-scan.
