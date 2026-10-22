# Security Policy

zero-hour is a security tool, so a flaw in it matters more than usual. Thank you for
reporting responsibly.

## Report a vulnerability in zero-hour itself

Please **do not open a public issue**. Use GitHub private vulnerability reporting:

1. Go to the [Security tab](https://github.com/akshitkhokhani/zero-hour/security) of this repo.
2. Click **Report a vulnerability**.
3. Include the affected version or commit, steps to reproduce, and the impact.

Examples of what we want to hear about:

- zero-hour writes, deletes or executes something while it should be read-only
- a secret value appears in any output format (md, json, sarif)
- a crafted lockfile, config or incident card makes zero-hour run code or read outside the scan scope
- fetched content (cards, web research) can steer the agent into unsafe actions
- the npm package or a release contains anything not in this repository

We acknowledge your report within 72 hours. We release each fix when it is ready. The
release notes credit you, unless you ask us not to.

## Supported versions

We support only the latest release. zero-hour downloads the skill and incident cards from
the `main` branch.

## Report a NEW incident (not a bug in zero-hour)

Do you know of a new breach, compromised package or exploited CVE that zero-hour must
check? Open an
[Incident card issue](https://github.com/akshitkhokhani/zero-hour/issues/new?template=incident-card.yml)
with primary sources. You can also send a pull request with a card (see [CONTRIBUTING.md](CONTRIBUTING.md)).
Do not post live malware, working exploits or anyone's secrets in an issue.
