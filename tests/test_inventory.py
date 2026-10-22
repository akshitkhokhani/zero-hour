"""Unit tests for scripts/zh_inventory.py (stdlib unittest only).

Every test writes a tiny, realistic lockfile/config into a temp dir and checks
name, version, source line and (where the format allows) direct/via.
"""
import json
import os
import sys
import tempfile
import textwrap
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "skills", "zero-hour", "scripts"))

import zh_inventory as I  # noqa: E402


def write(base, rel, text):
    path = os.path.join(base, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(text).lstrip("\n"))
    return path


def line_of(path, needle):
    with open(path, encoding="utf-8") as fh:
        for i, l in enumerate(fh, 1):
            if needle in l:
                return i
    raise AssertionError("%r not in %s" % (needle, path))


def by_name(pkgs):
    return {p["name"]: p for p in pkgs}


class TmpCase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.d = self._td.name

    def tearDown(self):
        self._td.cleanup()


# ------------------------------------------------------------------ npm family

class TestNpmLock(TmpCase):
    V3 = """
    {
      "name": "app",
      "version": "1.0.0",
      "lockfileVersion": 3,
      "requires": true,
      "packages": {
        "": {
          "name": "app",
          "version": "1.0.0",
          "dependencies": {
            "a": "^1.0.0"
          },
          "devDependencies": {
            "jest-lite": "^2.0.0"
          }
        },
        "node_modules/a": {
          "version": "1.0.0",
          "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
          "dependencies": {
            "b": "^2.0.0",
            "c": "^3.0.0"
          }
        },
        "node_modules/a/node_modules/c": {
          "version": "3.1.0"
        },
        "node_modules/b": {
          "version": "2.0.1"
        },
        "node_modules/c": {
          "version": "1.0.0"
        },
        "node_modules/jest-lite": {
          "version": "2.0.0",
          "dev": true
        },
        "node_modules/linked": {
          "resolved": "packages/linked",
          "link": true
        }
      }
    }
    """

    def test_v3_transitive_chain_and_nested(self):
        p = write(self.d, "package-lock.json", self.V3)
        pkgs = I.parse_npm_lock(p, self.d)
        keyed = {(x["name"], x["version"]): x for x in pkgs}
        self.assertNotIn("linked", by_name(pkgs))  # link entries skipped

        a = keyed[("a", "1.0.0")]
        self.assertTrue(a["direct"])
        self.assertEqual(a["via"], ["a"])
        self.assertEqual(a["line"], line_of(p, '"node_modules/a": {'))
        self.assertEqual(a["source"], "package-lock.json")
        self.assertEqual(a["ecosystem"], "npm")

        b = keyed[("b", "2.0.1")]
        self.assertFalse(b["direct"])
        self.assertEqual(b["via"], ["a", "b"])  # app -> a -> b
        self.assertEqual(b["line"], line_of(p, '"node_modules/b": {'))

        nested = keyed[("c", "3.1.0")]  # a's private copy wins over hoisted c@1.0.0
        self.assertFalse(nested["direct"])
        self.assertEqual(nested["via"], ["a", "c"])
        self.assertEqual(nested["line"], line_of(p, '"node_modules/a/node_modules/c": {'))

        hoisted = keyed[("c", "1.0.0")]  # nobody reaches it
        self.assertIsNone(hoisted["via"])

        dev = keyed[("jest-lite", "2.0.0")]
        self.assertTrue(dev["direct"])
        self.assertEqual(dev["scope"], "dev")
        self.assertEqual(a["scope"], "prod")

    def test_v1_nested_dependencies(self):
        p = write(self.d, "package-lock.json", """
        {
          "name": "old-app",
          "version": "1.0.0",
          "lockfileVersion": 1,
          "requires": true,
          "dependencies": {
            "express": {
              "version": "4.17.1",
              "requires": {"debug": "2.6.9"},
              "dependencies": {
                "debug": {"version": "2.6.9"}
              }
            },
            "mocha": {"version": "8.0.0", "dev": true}
          }
        }
        """)
        pkgs = I.parse_npm_lock(p, self.d)
        m = by_name(pkgs)
        self.assertEqual(m["express"]["version"], "4.17.1")
        self.assertTrue(m["express"]["direct"])
        self.assertEqual(m["express"]["via"], ["express"])
        self.assertEqual(m["debug"]["version"], "2.6.9")
        self.assertFalse(m["debug"]["direct"])
        self.assertEqual(m["debug"]["via"], ["express", "debug"])
        self.assertEqual(m["mocha"]["scope"], "dev")

    def test_garbage_is_empty(self):
        p = write(self.d, "package-lock.json", "{not json")
        self.assertEqual(I.parse_npm_lock(p, self.d), [])


class TestPnpmLock(TmpCase):
    def test_v9(self):
        write(self.d, "package.json", '{"dependencies": {"@scope/x": "^1.2.0"}, "devDependencies": {"y": "2"}}')
        p = write(self.d, "pnpm-lock.yaml", """
        lockfileVersion: '9.0'

        settings:
          autoInstallPeers: true

        importers:

          .:
            dependencies:
              '@scope/x':
                specifier: ^1.2.0
                version: 1.2.3

        packages:

          '@scope/x@1.2.3':
            resolution: {integrity: sha512-aaa}

          peer@1.0.0:
            resolution: {integrity: sha512-bbb}

          y@2.0.0(peer@1.0.0):
            resolution: {integrity: sha512-ccc}

        snapshots:

          '@scope/x@1.2.3': {}

          z@9.9.9: {}
        """)
        pkgs = I.parse_pnpm_lock(p, self.d)
        m = by_name(pkgs)
        self.assertEqual(set(m), {"@scope/x", "peer", "y"})  # snapshots/importers ignored
        self.assertEqual(m["@scope/x"]["version"], "1.2.3")
        self.assertEqual(m["@scope/x"]["line"], line_of(p, "  '@scope/x@1.2.3':"))
        self.assertTrue(m["@scope/x"]["direct"])
        self.assertEqual(m["@scope/x"]["scope"], "prod")
        self.assertEqual(m["y"]["version"], "2.0.0")  # peer suffix stripped
        self.assertEqual(m["y"]["scope"], "dev")
        self.assertIsNone(m["peer"]["direct"])

    def test_v6(self):
        p = write(self.d, "pnpm-lock.yaml", """
        lockfileVersion: '6.0'

        packages:

          /y@2.0.0:
            resolution: {integrity: sha512-ccc}
            dev: false

          /@scope/x@1.2.3(peer@1.0.0):
            resolution: {integrity: sha512-aaa}
        """)
        m = by_name(I.parse_pnpm_lock(p, self.d))
        self.assertEqual(m["y"]["version"], "2.0.0")
        self.assertEqual(m["y"]["line"], line_of(p, "  /y@2.0.0:"))
        self.assertEqual(m["@scope/x"]["version"], "1.2.3")

    def test_v5_slash_style(self):
        p = write(self.d, "pnpm-lock.yaml", """
        lockfileVersion: 5.4

        packages:

          /left-pad/1.3.0:
            resolution: {integrity: sha512-ddd}

          /@scope/z/4.5.6:
            resolution: {integrity: sha512-eee}
        """)
        m = by_name(I.parse_pnpm_lock(p, self.d))
        self.assertEqual(m["left-pad"]["version"], "1.3.0")
        self.assertEqual(m["@scope/z"]["version"], "4.5.6")

    def test_v5_peer_suffix(self):
        p = write(self.d, "pnpm-lock.yaml", """
        lockfileVersion: 5.4

        packages:

          /@scope/z/4.5.6_react@18.0.0:
            resolution: {integrity: sha512-eee}
        """)
        m = by_name(I.parse_pnpm_lock(p, self.d))
        self.assertEqual(m["@scope/z"]["version"], "4.5.6")


class TestYarnLock(TmpCase):
    def test_classic_v1(self):
        write(self.d, "package.json", '{"dependencies": {"@babel/code-frame": "^7.0.0"}}')
        p = write(self.d, "yarn.lock", """
        # THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
        # yarn lockfile v1


        "@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
          version "7.12.13"
          resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz"
          dependencies:
            "@babel/highlight" "^7.10.4"

        ms@2.1.2:
          version "2.1.2"
          resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.2.tgz"
        """)
        m = by_name(I.parse_yarn_lock(p, self.d))
        self.assertEqual(set(m), {"@babel/code-frame", "ms"})
        cf = m["@babel/code-frame"]
        self.assertEqual(cf["version"], "7.12.13")
        self.assertEqual(cf["line"], line_of(p, '"@babel/code-frame@^7.0.0"'))
        self.assertTrue(cf["direct"])
        self.assertEqual(m["ms"]["version"], "2.1.2")
        self.assertIsNone(m["ms"]["direct"])

    def test_berry(self):
        p = write(self.d, "yarn.lock", """
        # This file is generated by running "yarn install" inside your project.

        __metadata:
          version: 8
          cacheKey: 10c0

        "app@workspace:.":
          version: 0.0.0-use.local
          resolution: "app@workspace:."
          languageName: unknown
          linkType: soft

        "x@npm:^1.0.0":
          version: 1.2.3
          resolution: "x@npm:1.2.3"
          checksum: 10c0/abc
          languageName: node
          linkType: hard

        "@scope/y@npm:2.0.0, @scope/y@npm:^2.0.0":
          version: 2.0.0
          resolution: "@scope/y@npm:2.0.0"
          languageName: node
          linkType: hard
        """)
        m = by_name(I.parse_yarn_lock(p, self.d))
        self.assertEqual(set(m), {"x", "@scope/y"})  # workspace + __metadata skipped
        self.assertEqual(m["x"]["version"], "1.2.3")
        self.assertEqual(m["x"]["line"], line_of(p, '"x@npm:^1.0.0":'))
        self.assertEqual(m["@scope/y"]["version"], "2.0.0")

    def test_berry_patch_protocol_name(self):
        p = write(self.d, "yarn.lock", """
        "resolve@patch:resolve@npm%3A^1.20.0#~builtin<compat/resolve>":
          version: 1.22.8
          resolution: "resolve@patch:resolve@npm%3A1.22.8#~builtin<compat/resolve>::version=1.22.8"
        """)
        self.assertEqual([x["name"] for x in I.parse_yarn_lock(p, self.d)], ["resolve"])


class TestBunLock(TmpCase):
    def test_jsonc_trailing_commas(self):
        write(self.d, "package.json", '{"dependencies": {"ms": "^2.1.3"}}')
        p = write(self.d, "bun.lock", """
        {
          // bun text lockfile
          "lockfileVersion": 1,
          "workspaces": {
            "": {
              "name": "app",
              "dependencies": {
                "ms": "^2.1.3",
              },
            },
          },
          "packages": {
            "ms": ["ms@2.1.3", "", {}, "sha512-aaa"],
            "@types/node": ["@types/node@22.7.4", "", { "dependencies": { "undici-types": "~6.19.2" } }, "sha512-bbb"],
            "local-lib": ["local-lib@workspace:packages/local-lib"],
          },
        }
        """)
        m = by_name(I.parse_bun_lock(p, self.d))
        self.assertEqual(set(m), {"ms", "@types/node"})
        self.assertEqual(m["ms"]["version"], "2.1.3")
        self.assertEqual(m["ms"]["line"], line_of(p, '"ms": ["ms@2.1.3"'))
        self.assertTrue(m["ms"]["direct"])
        self.assertEqual(m["@types/node"]["version"], "22.7.4")
        self.assertIsNone(m["@types/node"]["direct"])


# ------------------------------------------------------------------ python family

class TestRequirements(TmpCase):
    def test_pinned_extras_unpinned(self):
        p = write(self.d, "requirements.txt", """
        # prod deps
        -r base.txt
        --index-url https://pypi.org/simple
        requests[security,socks]==2.32.3  # pinned with extras
        Django>=4.2,<5
        flask
        numpy==1.26.4 ; python_version >= "3.9"
        urllib3===2.2.3 \\
            --hash=sha256:abc
        git+https://github.com/org/repo.git#egg=thing
        """)
        pkgs = I.parse_requirements(p, self.d)
        m = by_name(pkgs)
        self.assertEqual(set(m), {"requests", "Django", "flask", "numpy", "urllib3"})
        self.assertEqual(m["requests"]["version"], "2.32.3")
        self.assertEqual(m["requests"]["line"], line_of(p, "requests[security"))
        self.assertIsNone(m["Django"]["version"])
        self.assertIsNone(m["flask"]["version"])
        self.assertEqual(m["numpy"]["version"], "1.26.4")
        self.assertEqual(m["urllib3"]["version"], "2.2.3")
        self.assertTrue(all(x["direct"] for x in pkgs))
        self.assertTrue(all(x["ecosystem"] == "PyPI" for x in pkgs))


class TestPipfileLock(TmpCase):
    def test_default_and_develop(self):
        p = write(self.d, "Pipfile.lock", """
        {
            "_meta": {
                "hash": {"sha256": "abc"},
                "pipfile-spec": 6
            },
            "default": {
                "requests": {
                    "hashes": ["sha256:abc"],
                    "version": "==2.32.3"
                }
            },
            "develop": {
                "pytest": {
                    "version": "==8.3.3"
                }
            }
        }
        """)
        m = by_name(I.parse_pipfile_lock(p, self.d))
        self.assertEqual(m["requests"]["version"], "2.32.3")
        self.assertEqual(m["requests"]["line"], line_of(p, '"requests": {'))
        self.assertEqual(m["requests"]["scope"], "prod")
        self.assertEqual(m["pytest"]["version"], "8.3.3")
        self.assertEqual(m["pytest"]["scope"], "dev")


class TestUvLock(TmpCase):
    UV = """
    version = 1
    requires-python = ">=3.12"

    [[package]]
    name = "crewai"
    version = "0.86.0"
    source = { registry = "https://pypi.org/simple" }
    dependencies = [
        { name = "litellm" },
        { name = "pydantic" },
    ]
    sdist = { url = "https://files.pythonhosted.org/crewai-0.86.0.tar.gz", hash = "sha256:aaa", size = 1 }

    [[package]]
    name = "litellm"
    version = "1.107.0"
    source = { registry = "https://pypi.org/simple" }
    dependencies = [{ name = "httpx" }]

    [[package]]
    name = "httpx"
    version = "0.27.2"
    source = { registry = "https://pypi.org/simple" }

    [[package]]
    name = "litellm-app"
    version = "0.1.0"
    source = { editable = "." }
    dependencies = [
        { name = "crewai" },
    ]

    [package.metadata]
    requires-dist = [{ name = "crewai", specifier = ">=0.80" }]

    [[package]]
    name = "pydantic"
    version = "2.9.2"
    source = { registry = "https://pypi.org/simple" }

    [[package]]
    name = "orphan"
    version = "1.0.0"
    source = { registry = "https://pypi.org/simple" }
    """

    def test_root_bfs_via_chain(self):
        p = write(self.d, "uv.lock", self.UV)
        pkgs = I.parse_toml_packages(p, self.d, "PyPI")
        m = by_name(pkgs)
        self.assertNotIn("litellm-app", m)  # the editable root is the project itself
        self.assertEqual(m["litellm"]["version"], "1.107.0")
        self.assertEqual(m["litellm"]["line"], line_of(p, 'name = "litellm"\n'))
        self.assertFalse(m["litellm"]["direct"])
        self.assertEqual(m["litellm"]["via"], ["crewai", "litellm"])
        self.assertTrue(m["crewai"]["direct"])
        self.assertEqual(m["crewai"]["via"], ["crewai"])
        self.assertEqual(m["httpx"]["via"], ["crewai", "litellm", "httpx"])
        self.assertEqual(m["pydantic"]["via"], ["crewai", "pydantic"])
        self.assertIsNone(m["orphan"]["via"])
        self.assertFalse(m["orphan"]["direct"])

    def test_registered_in_lockfile_table(self):
        p = write(self.d, "uv.lock", self.UV)
        self.assertEqual(len(I.LOCKFILES["uv.lock"](p, self.d)), 5)


class TestPoetryLock(TmpCase):
    def test_pyproject_direct_and_package_dependencies(self):
        write(self.d, "pyproject.toml", """
        [tool.poetry]
        name = "svc"

        [tool.poetry.dependencies]
        python = "^3.11"
        Requests = "^2.32"

        [build-system]
        requires = ["poetry-core"]
        """)
        p = write(self.d, "poetry.lock", """
        # This file is automatically @generated by Poetry 1.8.3 and should not be changed by hand.

        [[package]]
        name = "certifi"
        version = "2024.8.30"
        description = "Python package for providing Mozilla's CA Bundle."
        optional = false
        python-versions = ">=3.6"
        files = [
            {file = "certifi-2024.8.30-py3-none-any.whl", hash = "sha256:aaa"},
        ]

        [[package]]
        name = "requests"
        version = "2.32.3"
        description = "Python HTTP for Humans."
        optional = false
        python-versions = ">=3.8"
        files = []

        [package.dependencies]
        certifi = ">=2017.4.17"

        [package.extras]
        socks = ["PySocks (>=1.5.6,!=1.5.7)"]

        [metadata]
        lock-version = "2.0"
        python-versions = "^3.11"
        content-hash = "abc"
        """)
        m = by_name(I.LOCKFILES["poetry.lock"](p, self.d))
        self.assertEqual(set(m), {"certifi", "requests"})
        self.assertEqual(m["requests"]["version"], "2.32.3")
        self.assertEqual(m["requests"]["line"], line_of(p, 'name = "requests"'))
        self.assertTrue(m["requests"]["direct"])
        self.assertEqual(m["certifi"]["version"], "2024.8.30")
        self.assertFalse(m["certifi"]["direct"])
        self.assertEqual(m["certifi"]["via"], ["requests", "certifi"])


class TestCargoLock(TmpCase):
    def test_packages(self):
        p = write(self.d, "Cargo.lock", """
        # This file is automatically @generated by Cargo.
        version = 3

        [[package]]
        name = "app"
        version = "0.1.0"
        dependencies = [
         "serde",
         "tokio 1.40.0",
        ]

        [[package]]
        name = "serde"
        version = "1.0.210"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        checksum = "aaa"

        [[package]]
        name = "tokio"
        version = "1.40.0"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        """)
        pkgs = I.LOCKFILES["Cargo.lock"](p, self.d)
        m = by_name(pkgs)
        self.assertEqual(m["serde"]["version"], "1.0.210")
        self.assertEqual(m["serde"]["line"], line_of(p, 'name = "serde"'))
        self.assertEqual(m["tokio"]["version"], "1.40.0")
        self.assertEqual(m["serde"]["ecosystem"], "crates.io")


# ------------------------------------------------------------------ other ecosystems

class TestComposerLock(TmpCase):
    def test_packages_and_direct(self):
        write(self.d, "composer.json", """
        {
            "require": {"php": "^8.2", "monolog/monolog": "^3.7"},
            "require-dev": {"phpunit/phpunit": "^11.0"}
        }
        """)
        p = write(self.d, "composer.lock", """
        {
            "_readme": ["This file locks the dependencies of your project to a known state"],
            "content-hash": "abc",
            "packages": [
                {
                    "name": "monolog/monolog",
                    "version": "3.7.0",
                    "require": {"psr/log": "^2.0 || ^3.0"}
                },
                {
                    "name": "psr/log",
                    "version": "3.0.2"
                }
            ],
            "packages-dev": [
                {
                    "name": "phpunit/phpunit",
                    "version": "v11.4.1"
                }
            ]
        }
        """)
        m = by_name(I.parse_composer_lock(p, self.d))
        mono = m["monolog/monolog"]
        self.assertEqual(mono["version"], "3.7.0")
        self.assertEqual(mono["line"], line_of(p, '"name": "monolog/monolog"'))
        self.assertTrue(mono["direct"])
        self.assertEqual(mono["ecosystem"], "Packagist")
        self.assertFalse(m["psr/log"]["direct"])
        self.assertEqual(m["phpunit/phpunit"]["version"], "11.4.1")
        self.assertEqual(m["phpunit/phpunit"]["scope"], "dev")
        self.assertTrue(m["phpunit/phpunit"]["direct"])


class TestGoMod(TmpCase):
    def test_block_and_single_and_indirect(self):
        p = write(self.d, "go.mod", """
        module example.com/app

        go 1.22

        require github.com/single/line v0.3.0

        require (
        \tgithub.com/gin-gonic/gin v1.10.0
        \tgolang.org/x/crypto v0.27.0 // indirect
        )
        """)
        m = by_name(I.parse_go_mod(p, self.d))
        self.assertEqual(set(m), {"github.com/single/line", "github.com/gin-gonic/gin", "golang.org/x/crypto"})
        gin = m["github.com/gin-gonic/gin"]
        self.assertEqual(gin["version"], "1.10.0")  # leading v cleaned
        self.assertEqual(gin["line"], line_of(p, "gin-gonic/gin"))
        self.assertTrue(gin["direct"])
        self.assertFalse(m["golang.org/x/crypto"]["direct"])
        self.assertTrue(m["github.com/single/line"]["direct"])
        self.assertEqual(m["github.com/single/line"]["ecosystem"], "Go")


class TestGemfileLock(TmpCase):
    def test_specs(self):
        p = write(self.d, "Gemfile.lock", """
        GEM
          remote: https://rubygems.org/
          specs:
            actionpack (7.1.3)
              actionview (= 7.1.3)
            nokogiri (1.16.2-arm64-darwin)
              racc (~> 1.4)
            racc (1.8.1)

        PLATFORMS
          arm64-darwin

        DEPENDENCIES
          nokogiri
        """)
        pkgs = I.parse_gemfile_lock(p, self.d)
        m = by_name(pkgs)
        self.assertEqual(set(m), {"actionpack", "nokogiri", "racc"})  # nested reqs not counted
        self.assertEqual(m["actionpack"]["version"], "7.1.3")
        self.assertEqual(m["nokogiri"]["version"], "1.16.2")  # platform suffix dropped
        self.assertEqual(m["racc"]["line"], line_of(p, "    racc (1.8.1)"))


# ------------------------------------------------------------------ containers / CI / runtimes

class TestImages(unittest.TestCase):
    def test_image_ref(self):
        self.assertEqual(I.image_ref("php:8.3.30-apache"), ("php", "8.3.30-apache"))
        self.assertEqual(I.image_ref("docker.io/library/Python:3.12-slim"), ("python", "3.12-slim"))
        self.assertEqual(I.image_ref("ghcr.io/org/app:1.2@sha256:" + "a" * 64), ("ghcr.io/org/app", "1.2"))
        self.assertEqual(I.image_ref("localhost:5000/app"), ("localhost:5000/app", None))
        self.assertEqual(I.image_ref("ubuntu"), ("ubuntu", None))

    def test_runtime_from_image(self):
        rt = I.runtime_from_image("php", "8.3.30-apache", "Dockerfile", 3)
        self.assertEqual(len(rt), 1)
        self.assertEqual(rt[0]["name"], "php")
        self.assertEqual(rt[0]["version"], "8.3.30")
        self.assertIn("mod_php", rt[0]["sapi"])
        self.assertEqual(I.runtime_from_image("php", "8.2-fpm-alpine", "x", 1)[0]["sapi"], "fpm")
        wp = I.runtime_from_image("wordpress", "6.6-php8.2-apache", "compose.yaml", 4)[0]
        self.assertEqual((wp["name"], wp["version"]), ("php", "8.2"))
        self.assertIn("mod_php", wp["sapi"])
        self.assertEqual(I.runtime_from_image("python", "3.12-slim", "x", 1)[0]["version"], "3.12")
        self.assertEqual(I.runtime_from_image("node", "22", "x", 1)[0]["version"], "22")
        self.assertEqual(I.runtime_from_image("redis", "7", "x", 1), [])


class TestDockerfile(TmpCase):
    def test_multistage(self):
        p = write(self.d, "Dockerfile", """
        # syntax=docker/dockerfile:1
        FROM --platform=$BUILDPLATFORM node:22-alpine AS assets
        RUN npm ci
        FROM assets AS test
        RUN npm test
        FROM php:8.3.30-apache
        COPY --from=assets /app/dist /var/www/html
        RUN echo "session.upload_progress.enabled=1" > /usr/local/etc/php/conf.d/zz-upload.ini \\
            && echo "memory_limit=512M" >> /usr/local/etc/php/conf.d/zz-upload.ini
        FROM scratch AS empty
        FROM ${BASE_IMAGE}
        FROM debian:12@sha256:%s
        """ % ("b" * 64))
        images, runtimes, ini = I.parse_dockerfile(p, self.d)
        names = [(x["name"], x["tag"]) for x in images]
        self.assertEqual(names, [("node", "22-alpine"), ("php", "8.3.30-apache"), ("debian", "12")])
        self.assertNotIn("assets", [x["name"] for x in images])  # stage ref, not an image
        php_img = images[1]
        self.assertEqual(php_img["line"], line_of(p, "FROM php:8.3.30-apache"))
        self.assertFalse(php_img["pinned"])
        self.assertTrue(images[2]["pinned"])

        php = [r for r in runtimes if r["name"] == "php"]
        self.assertEqual(len(php), 1)
        self.assertEqual(php[0]["version"], "8.3.30")
        self.assertIn("mod_php", php[0]["sapi"])
        self.assertEqual(php[0]["line"], php_img["line"])
        self.assertIn("node", [r["name"] for r in runtimes])

        kv = {x["key"]: x for x in ini}
        self.assertEqual(kv["session.upload_progress.enabled"]["value"], "1")
        self.assertEqual(kv["session.upload_progress.enabled"]["line"], line_of(p, "session.upload_progress"))
        self.assertEqual(kv["memory_limit"]["value"], "512M")


class TestCompose(TmpCase):
    def test_images_and_runtimes(self):
        p = write(self.d, "docker-compose.yml", """
        services:
          wp:
            image: wordpress:6.6-php8.2-apache
            ports: ["8080:80"]
          db:
            image: "mysql:8.0"  # database
          api:
            image: ${REGISTRY}/api:latest
            build: .
        """)
        images, runtimes = I.parse_compose(p, self.d)
        self.assertEqual([(x["name"], x["tag"]) for x in images], [("wordpress", "6.6-php8.2-apache"), ("mysql", "8.0")])
        self.assertEqual(images[0]["line"], line_of(p, "wordpress:6.6"))
        self.assertEqual(len(runtimes), 1)
        self.assertEqual((runtimes[0]["name"], runtimes[0]["version"]), ("php", "8.2"))
        self.assertEqual(runtimes[0]["source"], "docker-compose.yml")


class TestWorkflow(TmpCase):
    def test_uses_pinned_vs_tag(self):
        sha = "11bd71901bbe5b1630ceea73d27597364c9af683"
        p = write(self.d, ".github/workflows/ci.yml", """
        name: ci
        on: [push]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@%s # v4.2.2
              - uses: actions/setup-node@v4
              - name: codeql
                uses: github/codeql-action/init@v3
              - uses: ./.github/actions/local
              - uses: docker://alpine:3.20
        """ % sha)
        acts = I.parse_workflow(p, self.d)
        self.assertEqual(len(acts), 3)
        co, node, cql = acts
        self.assertEqual(co["name"], "actions/checkout")
        self.assertEqual(co["ref"], sha)
        self.assertTrue(co["pinned"])
        self.assertEqual(co["line"], line_of(p, "actions/checkout@"))
        self.assertEqual(node["ref"], "v4")
        self.assertFalse(node["pinned"])
        self.assertEqual(cql["name"], "github/codeql-action")
        self.assertEqual(cql["path"], "github/codeql-action/init")
        self.assertEqual(co["source"], os.path.join(".github", "workflows", "ci.yml"))


class TestPhpIni(TmpCase):
    def test_keys(self):
        p = write(self.d, "php.ini", """
        [PHP]
        ; memory_limit = 1G
        memory_limit = 256M
        session.upload_progress.enabled = On
        fatal_error_backtraces = "1"
        display_errors = Off
        """)
        kv = {x["key"]: x for x in I.parse_php_ini(p, self.d)}
        self.assertEqual(set(kv), {"memory_limit", "session.upload_progress.enabled", "fatal_error_backtraces"})
        self.assertEqual(kv["memory_limit"]["value"], "256M")
        self.assertEqual(kv["memory_limit"]["line"], line_of(p, "memory_limit = 256M"))
        self.assertEqual(kv["session.upload_progress.enabled"]["value"], "On")
        self.assertEqual(kv["fatal_error_backtraces"]["value"], "1")


# ------------------------------------------------------------------ build()

class TestIgnore(TmpCase):
    def test_zerohourignore_directory(self):
        write(self.d, ".zerohourignore", "# comment\nexamples/\nlegacy\n")
        write(self.d, "requirements.txt", "requests==2.32.3\n")
        write(self.d, "examples/requirements.txt", "litellm==1.107.0\n")
        write(self.d, "legacy/deep/requirements.txt", "django==1.0\n")
        inv = I.build(self.d, include_host=False)
        names = {p["name"] for p in inv["packages"]}
        self.assertEqual(names, {"requests"})
        self.assertEqual(inv["files"], ["requirements.txt"])

    def test_zerohourignore_glob_dir(self):
        write(self.d, ".zerohourignore", "test-*\n")
        write(self.d, "test-data/requirements.txt", "litellm==1.107.0\n")
        write(self.d, "app/requirements.txt", "requests==2.32.3\n")
        names = {p["name"] for p in I.build(self.d, include_host=False)["packages"]}
        self.assertEqual(names, {"requests"})

    def test_zerohourignore_single_file(self):
        write(self.d, ".zerohourignore", "docs/requirements.txt\n")
        write(self.d, "docs/requirements.txt", "litellm==1.107.0\n")
        names = {p["name"] for p in I.build(self.d, include_host=False)["packages"]}
        self.assertNotIn("litellm", names)


class TestBuild(TmpCase):
    def test_aggregate(self):
        d = self.d
        write(d, "package.json", '{"name": "app", "dependencies": {"a": "^1.0.0"}}')
        write(d, "package-lock.json", TestNpmLock.V3)
        write(d, "node_modules/.package-lock.json", json.dumps(
            {"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0"}}}))
        write(d, "node_modules/evil/package-lock.json", '{"packages": {"node_modules/zzz": {"version": "6.6.6"}}}')
        write(d, "api/requirements.txt", "requests==2.32.3\n")
        write(d, "api/pyproject.toml", '[project]\nname = "api"\n')
        write(d, "web/package.json", '{"name": "web"}')  # manifest without lock
        write(d, "Dockerfile", "FROM php:8.3.30-apache\n")
        write(d, "deploy/compose.yaml", "services:\n  wp:\n    image: wordpress:6.6-php8.2-apache\n")
        write(d, ".github/workflows/ci.yml", "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n")
        write(d, "docker/php/conf.d/uploads.ini", "session.upload_progress.enabled = 1\n")
        write(d, ".nvmrc", "v22.9.0\n")
        write(d, "composer.json", '{"config": {"platform": {"php": "8.2.12"}}}')
        write(d, ".venv/lib/python3.12/site-packages/litellm-1.107.0.dist-info/METADATA",
              "Metadata-Version: 2.1\nName: litellm\nVersion: 1.107.0\n")
        write(d, "bun.lockb", "\x00binary")

        inv = I.build(d, include_host=False)
        self.assertEqual(inv["root"], os.path.abspath(d))
        self.assertEqual(inv["host_packages"], [])

        pk = {(p["name"], p["version"], p["source"], p["scope"]) for p in inv["packages"]}
        self.assertIn(("b", "2.0.1", "package-lock.json", "prod"), pk)
        self.assertIn(("requests", "2.32.3", os.path.join("api", "requirements.txt"), None), pk)
        self.assertIn(("a", "1.0.0", os.path.join("node_modules", ".package-lock.json"), "installed"), pk)
        sp = os.path.join(".venv", "lib", "python3.12", "site-packages")
        self.assertIn(("litellm", "1.107.0", sp, "installed"), pk)
        self.assertNotIn("zzz", {p["name"] for p in inv["packages"]})  # node_modules pruned

        self.assertEqual(len(inv["site_packages"]), 1)
        self.assertIn(("php", "8.3.30-apache"), {(i["name"], i["tag"]) for i in inv["images"]})
        self.assertIn(("wordpress", "6.6-php8.2-apache"), {(i["name"], i["tag"]) for i in inv["images"]})
        rts = {(r["name"], r["version"], r["origin"]) for r in inv["runtimes"]}
        self.assertIn(("php", "8.3.30", "image php:8.3.30-apache"), rts)
        self.assertIn(("php", "8.2", "image wordpress:6.6-php8.2-apache"), rts)
        self.assertIn(("node", "22.9.0", "version file"), rts)
        self.assertIn(("php", "8.2.12", "composer platform"), rts)
        self.assertEqual([a["name"] for a in inv["actions"]], ["actions/checkout"])
        self.assertIn(("session.upload_progress.enabled", "1"), {(x["key"], x["value"]) for x in inv["ini"]})
        self.assertIn(os.path.join("web", "package.json"), inv["manifests_without_lock"])
        self.assertNotIn("package.json", inv["manifests_without_lock"])
        self.assertNotIn(os.path.join("api", "pyproject.toml"), inv["manifests_without_lock"])
        self.assertTrue(any("bun.lockb" in n for n in inv["notes"]))
        for f in ("package-lock.json", "Dockerfile", os.path.join("deploy", "compose.yaml"),
                  os.path.join(".github", "workflows", "ci.yml")):
            self.assertIn(f, inv["files"])
        self.assertEqual(I.summary(inv).get("npm", 0) > 0, True)

    def test_empty_dir(self):
        inv = I.build(self.d, include_host=False)
        self.assertEqual(inv["packages"], [])
        self.assertEqual(inv["images"], [])


if __name__ == "__main__":
    unittest.main()
