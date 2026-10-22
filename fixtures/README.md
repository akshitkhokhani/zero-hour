# zero-hour test fixtures

Small fake projects that the end-to-end tests (`tests/test_e2e.py`) scan. Each one
mimics a real incident so zero-hour has something deterministic to find.

**Every indicator of compromise (IOC) in here is inert.** Nothing in this folder
can run code, download anything or touch your machine, even if you open a fixture
in an editor, an IDE or an AI coding agent. That matters because two of the real
attacks spread exactly that way (agent hooks and editor tasks that run on open).

zero-hour finds IOCs by **substring search**, so a fixture only needs the IOC
*text* to exist. It never needs the IOC to *work*. We use that to keep every
planted file harmless:

| Fixture | Planted IOC | Why it is inert |
|---|---|---|
| `litellm-app/.venv/lib/python3.12/site-packages/cook.pth` | the text `import cook` | The file is one comment line (`# ...`). Python ignores comment lines in `.pth` files, and there is no `cook` module anywhere. The `.venv` is not a real environment (no interpreter, no `pyvenv.cfg`). |
| `litellm-app/.venv/.../litellm-1.107.0.dist-info/METADATA` | installed litellm 1.107.0 | Metadata text only. No package code is present. |
| `litellm-app/uv.lock` | `litellm 1.107.0` via `crewai` | A lockfile is data. Nothing is installed from it unless you run `uv sync` yourself. **Don't.** |
| `php-app/Dockerfile`, `php-app/php.ini` | `php:8.3.30-apache` + `session.upload_progress.enabled = On` | Config text. Nothing is built or run unless you run `docker build` yourself. |
| `shai-hulud-npm/package-lock.json` | `tensorlake 0.5.144` via `some-sdk` | Lockfile only; there is no `node_modules`. **Do not run `npm install` here.** |
| `shai-hulud-npm/.claude/settings.json` | SessionStart hook mentioning `curl ... iseekaigogo.com ... \| sh` | The whole command is wrapped in `echo '...'`, so if an agent does run the hook it only prints a line of text. |
| `shai-hulud-npm/.vscode/tasks.json` | `runOn: folderOpen` task mentioning `node .vscode/Math_Symbol.js` | Same: the command is `echo '...'`, and `Math_Symbol.js` does not exist. VS Code also asks before running automatic tasks. |
| `clean-app/` | none | Must produce zero red findings. |

Rules for adding fixtures:

1. Never commit a working payload, a real malicious package, a binary, or a live URL
   that is fetched. IOC text goes inside comments or `echo '...'` strings.
2. Never add install scripts (`preinstall`, `postinstall`, `setup.py`) that do anything.
3. Keep the fixture as small as possible: only what a test asserts on.
4. If a repo-level `.gitignore` is added, make sure `fixtures/**/.venv` is not ignored,
   or the litellm fixture loses its IOC.
