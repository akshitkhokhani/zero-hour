"""Unit tests for scripts/zh_versions.py (stdlib unittest only)."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "skills", "zero-hour", "scripts"))

import zh_versions as V  # noqa: E402


def assert_order(tc, seq):
    for a, b in zip(seq, seq[1:]):
        tc.assertEqual(V.cmp(a, b), -1, "%s should be < %s" % (a, b))
        tc.assertEqual(V.cmp(b, a), 1, "%s should be > %s" % (b, a))
        tc.assertLess(V.vkey(a), V.vkey(b))


class TestOrdering(unittest.TestCase):
    def test_semver_numeric_not_lexicographic(self):
        assert_order(self, ["0.9.9", "1.2.3", "1.9.0", "1.10.0", "2.0.0", "10.0.0"])

    def test_semver_prerelease_before_release(self):
        assert_order(self, ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0-rc.1", "1.0.0"])
        self.assertEqual(V.cmp("1.0.0-rc.1", "1.0.0"), -1)
        self.assertEqual(V.cmp("2.0.0-beta.2", "1.9.9"), 1)

    def test_pep440_ordering(self):
        assert_order(self, ["1.0.dev1", "1.0a1", "1.0b1", "1.0rc1", "1.0", "1.0.post1", "1.0.1"])

    def test_trailing_zeros_equal(self):
        self.assertEqual(V.cmp("1.0", "1.0.0"), 0)
        self.assertEqual(V.cmp("1", "1.0.0"), 0)
        self.assertEqual(V.vkey("2.0"), V.vkey("2.0.0.0"))

    def test_leading_v_and_equals(self):
        self.assertEqual(V.cmp("v1.2.3", "1.2.3"), 0)
        self.assertEqual(V.cmp("V2.0", "2.0.0"), 0)
        self.assertEqual(V.cmp("==1.4.0", "1.4"), 0)

    def test_build_metadata_ignored(self):
        self.assertEqual(V.cmp("1.2.3+local.7", "1.2.3"), 0)

    def test_clean(self):
        self.assertIsNone(V.clean(None))
        self.assertEqual(V.clean(" v1.2.3 "), "1.2.3")
        self.assertEqual(V.clean("1.2.3+abc"), "1.2.3")

    def test_none_and_garbage_do_not_crash(self):
        V.vkey(None)
        V.vkey("latest")
        self.assertEqual(V.cmp("latest", "1.0"), -1)


class TestInRange(unittest.TestCase):
    def test_fixed_is_exclusive(self):
        r = {"introduced": "1.100.0", "fixed": "1.107.1"}
        self.assertTrue(V.in_range("1.107.0", r))
        self.assertTrue(V.in_range("1.100.0", r))
        self.assertFalse(V.in_range("1.107.1", r))
        self.assertFalse(V.in_range("1.99.9", r))
        self.assertFalse(V.in_range("2.0.0", r))

    def test_last_affected_is_inclusive(self):
        r = {"introduced": "1.107.0", "last_affected": "1.107.0"}
        self.assertTrue(V.in_range("1.107.0", r))
        self.assertFalse(V.in_range("1.106.9", r))
        self.assertFalse(V.in_range("1.107.1", r))

    def test_limit_is_exclusive(self):
        r = {"introduced": "2.0.0", "limit": "3.0.0"}
        self.assertTrue(V.in_range("2.5.0", r))
        self.assertFalse(V.in_range("3.0.0", r))

    def test_introduced_zero_and_missing(self):
        self.assertTrue(V.in_range("0.0.1", {"introduced": "0", "fixed": "1.0.0"}))
        self.assertTrue(V.in_range("0.9", {"fixed": "1.0.0"}))
        self.assertFalse(V.in_range("1.0.0", {"introduced": "0", "fixed": "1.0.0"}))

    def test_open_ended(self):
        self.assertTrue(V.in_range("99.0", {"introduced": "1.0"}))
        self.assertFalse(V.in_range("0.9", {"introduced": "1.0"}))

    def test_prerelease_of_fix_is_still_affected(self):
        self.assertTrue(V.in_range("1.0.0-rc.1", {"introduced": "0", "fixed": "1.0.0"}))
        self.assertTrue(V.in_range("8.3.30", {"introduced": "8.3.0", "fixed": "8.3.31"}))


class TestOsvRanges(unittest.TestCase):
    def test_flatten_multiple_pairs(self):
        aff = {"ranges": [
            {"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}, {"fixed": "1.2.0"},
                {"introduced": "2.0.0"}, {"fixed": "2.3.1"},
                {"introduced": "3.0.0"}]},
            {"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"last_affected": "4.0.5"}]},
            {"type": "GIT", "events": [{"introduced": "abc"}, {"fixed": "def"}]},
        ]}
        self.assertEqual(V.osv_ranges(aff), [
            {"introduced": "0", "fixed": "1.2.0"},
            {"introduced": "2.0.0", "fixed": "2.3.1"},
            {"introduced": "3.0.0"},
            {"introduced": "4.0.0", "last_affected": "4.0.5"},
        ])

    def test_empty(self):
        self.assertEqual(V.osv_ranges({}), [])
        self.assertEqual(V.osv_ranges({"ranges": None}), [])


class TestFixedVersionFor(unittest.TestCase):
    VULN = {"id": "GHSA-test", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "Some_Pkg"},
         "ranges": [{"type": "ECOSYSTEM", "events": [
             {"introduced": "0"}, {"fixed": "1.5.0"},
             {"introduced": "2.0.0"}, {"fixed": "2.4.0"}]}]},
        {"package": {"ecosystem": "PyPI", "name": "some-pkg"},
         "ranges": [{"type": "ECOSYSTEM", "events": [
             {"introduced": "2.0.0"}, {"fixed": "2.2.0"}]}]},
        {"package": {"ecosystem": "npm", "name": "other"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.0.1"}]}]},
    ]}

    def test_picks_smallest_applicable_fix(self):
        self.assertEqual(V.fixed_version_for("2.1.0", self.VULN, "PyPI", "some.pkg"), "2.2.0")
        self.assertEqual(V.fixed_version_for("1.0.0", self.VULN, "PyPI", "some-pkg"), "1.5.0")

    def test_not_affected_returns_none(self):
        self.assertIsNone(V.fixed_version_for("1.6.0", self.VULN, "PyPI", "some-pkg"))
        self.assertIsNone(V.fixed_version_for("3.0.0", self.VULN, "PyPI", "some-pkg"))
        self.assertIsNone(V.fixed_version_for("1.0.0", self.VULN, "PyPI", "unrelated"))

    def test_last_affected_only_has_no_fix(self):
        vuln = {"affected": [{"package": {"ecosystem": "npm", "name": "x"},
                              "ranges": [{"type": "SEMVER", "events": [
                                  {"introduced": "0"}, {"last_affected": "1.0.0"}]}]}]}
        self.assertIsNone(V.fixed_version_for("0.5.0", vuln, "npm", "x"))


class TestNames(unittest.TestCase):
    def test_pypi_normalization(self):
        for n in ("Some_Pkg", "some.pkg", "SOME-PKG", "some__pkg", "some-._pkg"):
            self.assertEqual(V.normalize_name("PyPI", n), "some-pkg")
        self.assertEqual(V.normalize_name("PyPI", "LiteLLM"), "litellm")

    def test_npm_lowercase_and_go_case_preserved(self):
        self.assertEqual(V.normalize_name("npm", "@Scope/Pkg"), "@scope/pkg")
        self.assertEqual(V.normalize_name("npm", "my_pkg"), "my_pkg")
        self.assertEqual(V.normalize_name("Go", "github.com/Foo/Bar"), "github.com/Foo/Bar")


class TestDistroBuild(unittest.TestCase):
    def test_distro_builds(self):
        for v in ("8.1.2-1ubuntu2.18", "8.2.7-1.el9", "7.4.33-1+deb11u5", "8.2.26-1~deb12u1",
                  "8.3.6-1.fc40"):
            self.assertTrue(V.looks_distro_build(v), v)

    def test_upstream_versions(self):
        for v in ("8.3.36", "8.3.30", "1.107.0", "2.1.3", "1.0.0-rc.1"):
            self.assertFalse(V.looks_distro_build(v), v)


if __name__ == "__main__":
    unittest.main()
