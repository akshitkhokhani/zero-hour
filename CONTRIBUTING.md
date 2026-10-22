# Contributing to zero-hour

Thanks for helping. The most useful contribution is a good **incident card**. Every
zero-hour user downloads a merged card on their next run.

## Add an incident card

1. Start from the template:

   ```bash
   python3 scripts/zerohour.py card template > incidents/<short-id>.json
   ```

2. Fill it in from **primary sources**:
   - the vendor or maintainer advisory
   - the registry record (npm, PyPI, …)
   - the CVE / GHSA / OSV entry
   - research write-ups from the team that found it

   Every claim needs a link in the card's sources.
3. Validate it:

   ```bash
   python3 scripts/zerohour.py card validate incidents/<short-id>.json
   ```

4. Rebuild the card index and run the tests:

   ```bash
   python3 tools/build_index.py
   python3 -m unittest discover -s tests
   ```

5. Open a pull request. The template has a checklist.

### Card rules

- **Cite sources.** No source, no merge.
- **No unverified IOCs.** Only file paths, hashes, domains and process names that a cited
  source reports. If sources disagree, say so in the card.
- **Order remediation safely.** Contain and disarm before you rotate credentials. Mark each
  step that is dangerous to run early. Example: revoking a token that a dead-man switch watches.
- **Inert fixtures only.** Test fixtures may mimic an IOC's *name and location* (a
  `cook.pth` with a comment in it, an unloaded plist), never its working payload.
- **No secrets, no live malware, no exploit code** anywhere in the repo.

## Code changes

- Scripts are **Python 3.9+ standard library only**. No new dependencies, in Python or in
  `package.json`. No install scripts.
- Keep everything **read-only by default**. Anything that writes needs an explicit flag
  and a per-step approval.
- Never print secret values. Redact.
- Add or update tests in `tests/` with fixtures in `fixtures/`, and run:

  ```bash
  python3 -m unittest discover -s tests -v
  python3 tools/build_index.py --check
  node bin/zerohour.js --help
  ```

- `SKILL.md` follows the [Agent Skills spec](https://agentskills.io): `name` and
  `description` frontmatter only, no vendor-specific tool names, under 500 lines.

## Don't have time for a PR?

Open an [Incident card issue](https://github.com/akshitkhokhani/zero-hour/issues/new?template=incident-card.yml)
with the facts and sources. A maintainer can turn it into a card.

When you contribute, you license your work under the [MIT License](LICENSE). You also agree
to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
