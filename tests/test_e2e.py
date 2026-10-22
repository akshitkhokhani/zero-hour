"""End-to-end tests: run the zero-hour CLI against the fixture projects.

Runs fully offline with a fresh, empty cache, so OSV/KEV are unavailable and only
the bundled incident cards in incidents/ produce verdicts. That keeps results
deterministic.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "scripts", "zerohour.py")
FIXTURES = os.path.join(ROOT, "fixtures")

LITELLM = "2026-10-21-litellm-1-107-0"
PHP2SHELL = "2026-10-21-php2shell"
TENSORLAKE = "2026-10-08-tensorlake-shai-hulud"
RED = ("compromised", "affected")
NUMBERED = re.compile(r"^\s*(?:#+\s*)?(?:\*\*)?(?:step\s*)?\d+[.):]\s", re.I)

_cache = {}


def scan(fixture, fmt="json"):
    """Run the CLI once per (fixture, format) and memoise (exit code, stdout, stderr)."""
    key = (fixture, fmt)
    if key not in _cache:
        with tempfile.TemporaryDirectory() as cache_dir:
            env = dict(os.environ, ZERO_HOUR_CACHE=cache_dir, PYTHONDONTWRITEBYTECODE="1")
            r = subprocess.run(
                [sys.executable, CLI, "scan", os.path.join(FIXTURES, fixture), "--offline",
                 "--no-remote-cards", "--no-host", "--format", fmt],
                cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
        _cache[key] = (r.returncode, r.stdout, r.stderr)
    return _cache[key]


def scan_json(tc, fixture):
    code, out, err = scan(fixture, "json")
    try:
        data = json.loads(out)
    except ValueError:
        tc.fail("CLI did not print JSON for %s (exit %s)\nstdout:\n%s\nstderr:\n%s"
                % (fixture, code, out[:2000], err[-2000:]))
    return code, data


def incident(tc, data, card_id):
    for inc in data.get("incidents", []):
        if inc.get("id") == card_id:
            return inc
    tc.fail("incident %s missing; got %s" % (card_id, [i.get("id") for i in data.get("incidents", [])]))


def tree_digest(path):
    h = hashlib.sha256()
    for d, dirs, files in os.walk(path):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(d, f)
            h.update(os.path.relpath(p, path).encode())
            with open(p, "rb") as fh:
                h.update(fh.read())
            h.update(str(os.stat(p).st_mtime_ns).encode())
    return h.hexdigest()


@unittest.skipUnless(os.path.exists(CLI), "scripts/zerohour.py not written yet")
class TestShape(unittest.TestCase):
    def test_json_contract(self):
        _, data = scan_json(self, "clean-app")
        self.assertEqual(data["tool"], "zero-hour")
        self.assertIn("version", data)
        self.assertTrue(data["root"].rstrip("/\\").endswith("clean-app"))
        self.assertIn("offline", str(data["intel"].get("osv", "")).lower())
        for k in ("compromised", "affected", "exposed", "review", "unknown", "clear"):
            self.assertIsInstance(data["summary"][k], int, k)
        for k in ("incidents", "advisories", "hygiene"):
            self.assertIsInstance(data[k], list, k)
        for inc in data["incidents"]:
            self.assertIn(inc["verdict"], ("compromised", "affected", "exposed", "clear", "unknown"))
            self.assertIn(inc["confidence"], ("high", "medium", "low"))
            for k in ("id", "title", "evidence", "steps"):
                self.assertIn(k, inc)

    def test_scan_is_read_only(self):
        for fx in ("litellm-app", "php-app", "shai-hulud-npm", "clean-app"):
            before = tree_digest(os.path.join(FIXTURES, fx))
            _cache.pop((fx, "json"), None)
            scan(fx, "json")
            self.assertEqual(before, tree_digest(os.path.join(FIXTURES, fx)), fx)


@unittest.skipUnless(os.path.exists(CLI), "scripts/zerohour.py not written yet")
class TestLitellm(unittest.TestCase):
    def test_compromised_via_crewai(self):
        code, data = scan_json(self, "litellm-app")
        inc = incident(self, data, LITELLM)
        self.assertEqual(inc["verdict"], "compromised", inc)
        blob = " ".join([" ".join(inc.get("via") or [])] +
                        [e.get("text", "") for e in inc.get("evidence", [])])
        self.assertIn("crewai", blob)
        self.assertIn("cook.pth", json.dumps(inc["evidence"]))
        self.assertGreaterEqual(data["summary"]["compromised"], 1)
        self.assertEqual(code, 2)

    def test_markdown_says_compromised(self):
        code, out, err = scan("litellm-app", "md")
        self.assertIn("COMPROMISED", out, err[-2000:])
        self.assertEqual(code, 2)


@unittest.skipUnless(os.path.exists(CLI), "scripts/zerohour.py not written yet")
class TestPhp(unittest.TestCase):
    def test_php2shell_affected(self):
        code, data = scan_json(self, "php-app")
        inc = incident(self, data, PHP2SHELL)
        self.assertEqual(inc["verdict"], "affected", inc)
        ev = json.dumps(inc["evidence"])
        self.assertIn("8.3.30", ev)
        self.assertEqual(code, 2)


@unittest.skipUnless(os.path.exists(CLI), "scripts/zerohour.py not written yet")
class TestShaiHulud(unittest.TestCase):
    def test_tensorlake_compromised_and_agent_hook_flagged(self):
        code, data = scan_json(self, "shai-hulud-npm")
        inc = incident(self, data, TENSORLAKE)
        self.assertEqual(inc["verdict"], "compromised", inc)
        files = {str(h.get("file") or "").replace("\\", "/") for h in data["hygiene"]}
        self.assertIn(".claude/settings.json", files, data["hygiene"])
        self.assertEqual(code, 2)

    def test_disarm_before_rotate_in_json_steps(self):
        _, data = scan_json(self, "shai-hulud-npm")
        steps = [s.get("step", "") for s in incident(self, data, TENSORLAKE)["steps"]]
        disarm = next((i for i, s in enumerate(steps) if re.search(r"disarm|monitor", s, re.I)), None)
        rotate = next((i for i, s in enumerate(steps) if re.search(r"rotat|revok", s, re.I)), None)
        self.assertIsNotNone(disarm, steps)
        self.assertIsNotNone(rotate, steps)
        self.assertLess(disarm, rotate, steps)

    def test_disarm_before_rotate_in_markdown(self):
        _, data = scan_json(self, "shai-hulud-npm")
        title = incident(self, data, TENSORLAKE)["title"]
        code, out, err = scan("shai-hulud-npm", "md")
        self.assertIn(title, out, err[-2000:])
        # The fix list is the numbered block that follows a line naming this incident.
        lines = out.splitlines()
        steps = []
        for i, l in enumerate(lines):
            if title not in l:
                continue
            block = []
            for nxt in lines[i + 1:]:
                if NUMBERED.match(nxt):
                    block.append(nxt)
                elif block and nxt.strip() and not nxt[:1].isspace():
                    break  # next unindented, unnumbered line ends the list
            if block:
                steps = block
                break
        disarm = next((i for i, l in enumerate(steps) if re.search(r"disarm|monitor", l, re.I)), None)
        rotate = next((i for i, l in enumerate(steps) if re.search(r"rotat", l, re.I)), None)
        self.assertIsNotNone(disarm, out)
        self.assertIsNotNone(rotate, out)
        self.assertLess(disarm, rotate, steps)


@unittest.skipUnless(os.path.exists(CLI), "scripts/zerohour.py not written yet")
class TestClean(unittest.TestCase):
    def test_no_red_findings(self):
        code, data = scan_json(self, "clean-app")
        red = [(i["id"], i["verdict"]) for i in data["incidents"] if i["verdict"] in RED]
        self.assertEqual(red, [])
        self.assertEqual(data["summary"]["compromised"], 0)
        self.assertEqual(data["summary"]["affected"], 0)
        self.assertFalse([h for h in data["hygiene"] if h.get("level") == "high"], data["hygiene"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
