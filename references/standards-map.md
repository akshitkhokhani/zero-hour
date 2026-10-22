# Standards map: finding type → ids

Load when writing the report or SARIF. Cite an id only from this table; if a finding has no
row, cite none. OWASP Top 10 = 2025 edition; ASVS = 5.0 (chapter level); SSDF = NIST SP 800-218
practices; CIS ids for cloud are in `deep-cloud.md`.

| Finding type | CWE | OWASP Top 10 2025 | ASVS 5.0 | NIST SSDF | SLSA / Scorecard |
|---|---|---|---|---|---|
| Malicious package/version installed | CWE-506, CWE-829 | A03 Software Supply Chain Failures | V15 Secure Coding & Architecture | PW.4, RV.1 | Scorecard Vulnerabilities |
| Known-vulnerable dependency | CWE-1395 | A03 | V15 | PW.4, RV.1, RV.2 | Vulnerabilities, Dependency-Update-Tool |
| Unmaintained / EOL component or runtime | CWE-1104 | A03 | V15 | PW.4 | Maintained |
| Unpinned dependency / action / image | CWE-829, CWE-494 | A03 | V15 | PW.4, PS.2 | Pinned-Dependencies; SLSA Build |
| Install/lifecycle scripts executing untrusted code | CWE-829 | A03 | V15 | PO.5, PW.4 | |
| Release without integrity/provenance | CWE-494 | A08 Software or Data Integrity Failures | V15 | PS.2, PS.3 | Signed-Releases; SLSA Build L2+ |
| Secret in code / git history | CWE-798 | A07 Authentication Failures | V13 Configuration | PS.1, PO.5 | |
| Over-privileged CI token / cloud identity | CWE-250, CWE-269 | A01 Broken Access Control | V8 Authorization | PO.5 | Token-Permissions |
| CI script injection (`${{ github.event.* }}`) | CWE-78, CWE-94 | A05 Injection | V1 Encoding & Sanitization | PW.5 | Dangerous-Workflow |
| `pull_request_target` + untrusted checkout | CWE-829 | A01 | V8 | PO.5, PS.1 | Dangerous-Workflow |
| Agent/IDE config that auto-runs commands (hooks, folderOpen tasks, MCP) | CWE-829, CWE-506 | A03 | V15 | PO.5 | |
| Public bucket / snapshot / DB | CWE-284, CWE-668 | A01 | V8, V14 Data Protection | PW.9 | |
| Wide-open firewall / security group | CWE-284 | A02 Security Misconfiguration | V13 | PW.9 | |
| Default or empty credentials | CWE-1392, CWE-521 | A07 Authentication Failures | V6 Authentication | PW.9 | |
| Missing authentication on service | CWE-306 | A07 | V6 | PW.9 | |
| No TLS / cleartext transport | CWE-319 | A04 | V12 Secure Communication | PW.9 | |
| Insecure default configuration | CWE-1188 | A02 | V13 | PW.9 | |
| Missing audit logging (e.g. CloudTrail off) | CWE-778 | A09 Security Logging & Alerting Failures | V16 Security Logging & Error Handling | PO.5 | |
| Memory-safety bug in runtime (e.g. use-after-free) | CWE-416 | A03 (as vulnerable component) | V15 | RV.1, RV.2 | |
| No branch protection / code review | — | — | — | PS.1 | Branch-Protection, Code-Review |

## Response / prioritisation
- Fix ordering: NIST SP 800-61 Rev. 3 (contain → eradicate/rotate → recover → lessons learned).
- Priority signals: CISA KEV (exploited) > OSV `MAL-` (malicious) > FIRST EPSS ≥ 0.1 > CVSS v4.
- Vulnerability ids: CVE, GHSA, OSV (`MAL-`, `PYSEC-`, ...). Report formats: SARIF 2.1.0, CycloneDX.
