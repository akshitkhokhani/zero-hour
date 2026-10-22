"""Regression tests for the pre-release security/correctness review. Stdlib only."""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import zh_hunt  # noqa: E402
import zh_intel  # noqa: E402
import zh_inventory as I  # noqa: E402
import zh_versions as V  # noqa: E402

CLI = os.path.join(REPO, "scripts", "zerohour.py")


def scan(path, *extra, cwd=None):
    env = dict(os.environ, ZERO_HOUR_CACHE=tempfile.mkdtemp())
    r = subprocess.run([sys.executable, CLI, "scan", path, "--offline", "--no-remote-cards", "--format", "json", *extra],
                       capture_output=True, text=True, env=env, cwd=cwd or REPO, timeout=120)
    return r.returncode, (json.loads(r.stdout) if r.stdout.strip().startswith("{") else r.stdout + r.stderr)


def write(d, rel, text):
    p = os.path.join(d, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(textwrap.dedent(text).lstrip("\n"))
    return p


def verdict(report, card_id):
    return next(i["verdict"] for i in report["incidents"] if i["id"] == card_id)


class NoCodeFromScannedRepo(unittest.TestCase):
    def test_planted_json_py_does_not_run(self):
        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, "PWNED")
            write(d, "json.py", "open(%r, 'w').write('x')\n" % marker)
            write(d, "requirements.txt", "requests==2.32.3\n")
            scan(".", cwd=d)  # with host probes on, from inside the project
            self.assertFalse(os.path.exists(marker))

    def test_git_config_fsmonitor_and_gpg_do_not_run(self):
        if not I.which_safe("git"):
            self.skipTest("git not installed")
        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, "PWNED")
            evil = write(d, "evil.sh", "#!/bin/sh\ntouch %s\n" % marker)
            os.chmod(evil, 0o755)
            subprocess.run(["git", "init", "-q", d], check=True)
            subprocess.run(["git", "-C", d, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q",
                            "--allow-empty", "-m", "x"], check=True)
            with open(os.path.join(d, ".git", "config"), "a") as fh:
                fh.write("[core]\n\tfsmonitor = %s\n[log]\n\tshowSignature = true\n[gpg]\n\tprogram = %s\n" % (evil, evil))
            write(d, "requirements.txt", "requests==2.32.3\n")
            scan(d, "--no-host", "--deep")
            self.assertFalse(os.path.exists(marker))


class NoFalseClear(unittest.TestCase):
    def test_malformed_lockfile_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "package-lock.json", "{ this is not json")
            _, r = scan(d, "--no-host")
            self.assertTrue(any("could not be parsed" in u for u in r["unknowns"]))

    def test_manifest_without_lock_is_unknown_not_clear(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "package.json", '{"dependencies": {"tensorlake": "0.5.144"}}')
            _, r = scan(d, "--no-host")
            self.assertEqual(verdict(r, "2026-10-08-tensorlake-shai-hulud"), "unknown")

    def test_empty_dir_is_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            _, r = scan(d, "--no-host")
            self.assertTrue(any("nothing to match" in u for u in r["unknowns"]))

    def test_dockerfile_arg_from_is_resolved(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "Dockerfile", "ARG PHP_VERSION=8.3.30\nFROM php:${PHP_VERSION}-apache\n")
            _, r = scan(d, "--no-host")
            self.assertEqual(verdict(r, "2026-10-21-php2shell"), "affected")

    def test_dockerfile_unresolved_arg_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "Dockerfile", "ARG PHP_VERSION\nFROM php:${PHP_VERSION}-apache\n")
            _, r = scan(d, "--no-host")
            self.assertEqual(verdict(r, "2026-10-21-php2shell"), "unknown")

    def test_major_only_tag_is_exposed_not_affected(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "Dockerfile", "FROM php:8-apache\n")
            _, r = scan(d, "--no-host")
            self.assertEqual(verdict(r, "2026-10-21-php2shell"), "exposed")

    def test_yarn_alias_resolves_real_name(self):
        with tempfile.TemporaryDirectory() as d:
            p = write(d, "yarn.lock", '''
            "tl@npm:tensorlake@0.5.144":
              version: 0.5.144
            ''')
            self.assertEqual([x["name"] for x in I.parse_yarn_lock(p, d)], ["tensorlake"])


class Robustness(unittest.TestCase):
    def test_bad_cards_fail_validation(self):
        with open(os.path.join(REPO, "incidents", "2026-10-21-php2shell.json")) as fh:
            base = json.load(fh)
        for mutate in (lambda c: c["remediation"][0].__setitem__("commands", ["rm -rf /"]),
                       lambda c: c["affected"][0].__setitem__("name", 5),
                       lambda c: c["affected"].append("x"),
                       lambda c: c.__setitem__("id", "../../etc/passwd")):
            c = json.loads(json.dumps(base))
            mutate(c)
            self.assertTrue(zh_intel.validate_card(c))

    def test_deep_chain_is_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            n = 3000
            pk = {"": {"dependencies": {"p0": "1.0.0"}}}
            for i in range(n):
                e = {"version": "1.0.0"}
                if i + 1 < n:
                    e["dependencies"] = {"p%d" % (i + 1): "1.0.0"}
                pk["node_modules/p%d" % i] = e
            p = write(d, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": pk}))
            out = I.parse_npm_lock(p, d)
            self.assertEqual(len(out), n)
            self.assertLessEqual(max(len(x["via"] or []) for x in out), I.MAX_CHAIN)

    def test_redacts_credentials_in_urls(self):
        t = zh_hunt.short("npx db-mcp postgresql://admin:Sup3rS3cret@db/app https://x.io/?token=abcdef123")
        self.assertNotIn("Sup3rS3cret", t)
        self.assertNotIn("abcdef123", t)

    def test_gh_exclusive_lower_bound(self):
        _, ranges = zh_intel.parse_gh_range("> 1.0.0, < 2.0.0")
        self.assertFalse(V.in_range("1.0.0", ranges[0]))
        self.assertTrue(V.in_range("1.0.1", ranges[0]))

    def test_osv_never_drops_ids(self):
        class FakeNet:
            status = {}
            def get_json(self, url, source, body=None, ttl=None, **kw):
                if body:
                    return {"results": [{"vulns": [{"id": "GHSA-%04d" % i} for i in range(5)] + [{"id": "MAL-2026-1"}]}]}
                return None  # every detail fetch fails
        hits = zh_intel.osv_scan(FakeNet(), [{"ecosystem": "npm", "name": "x", "version": "1.0.0"}], max_vulns=2)
        ids = [v["id"] for v in hits[("npm", "x", "1.0.0")]]
        self.assertIn("MAL-2026-1", ids)
        self.assertEqual(len(ids), 6)


if __name__ == "__main__":
    unittest.main()
