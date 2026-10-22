#!/usr/bin/env node
'use strict';

// zero-hour CLI shim. Zero dependencies. It does two things:
//   1. `zerohour install` -> installs the Agent Skill via the skills CLI.
//   2. everything else    -> runs scripts/zerohour.py with a local Python 3.9+.
// All child processes are spawned with an argument array (no shell strings),
// except the Windows npx fallback, which needs a shell to resolve npx.cmd.

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const PKG_ROOT = path.resolve(__dirname, '..');
const SCRIPT = path.join(PKG_ROOT, 'skills', 'zero-hour', 'scripts', 'zerohour.py');
const REPO = 'akshitkhokhani/zero-hour';
const IS_WIN = process.platform === 'win32';

function version() {
  try {
    return JSON.parse(fs.readFileSync(path.join(PKG_ROOT, 'package.json'), 'utf8')).version;
  } catch (_) {
    return 'unknown';
  }
}

const HELP = `zero-hour ${version()}
Today's breach. Your stack. Am I hit, and what do I do right now?

Usage:
  zerohour install [skills-cli args...]   Install the Agent Skill into your AI agents
                                          (runs: npx -y skills add ${REPO} [args...])
  zerohour scan [PATH] [options]          Check a project against live incidents (default: scan .)
      --deep                 also CI, agent configs, infra posture (read-only)
      --incident QUERY       focus on one incident, package or CVE (e.g. litellm)
      --format md|json|sarif output format (default: md)
      --out FILE             write the report to FILE
      --card FILE            add a local incident card (repeatable)
      --offline              no network; cached intel and bundled cards only
      --no-remote-cards      do not fetch community cards from GitHub
      --no-host              only the project: skip this machine's runtimes, images, envs, IOCs, agent configs
      --github               also use the GitHub CLI (gh), if already authenticated
      --all                  also show low-priority advisories (not exploited, low EPSS)
  zerohour pulse [--days N] [--format md|json]
                                          What is being exploited / new incident cards right now
  zerohour inventory [PATH]               Print the project inventory as JSON
  zerohour card validate FILE | card template | card add FILE
                                          Work with incident cards

  zerohour --help | --version             (zerohour scan --help for full options)

Exit codes: 0 nothing affected, 2 affected/compromised found, 3 error.
Read-only by default. Never prints secret values. No telemetry.
Docs: https://github.com/${REPO}`;

function runInstall(args) {
  const npxArgs = ['-y', 'skills', 'add', REPO, ...args];
  console.log('zero-hour: installing the skill with the skills CLI');
  console.log('  tip: add -g to install globally, or -a <agent> (e.g. -a codex) to target one agent.');
  let res;
  if (IS_WIN) {
    // npx is a .cmd shim on Windows; it must go through the shell. Arguments are
    // quoted individually to keep them as single tokens.
    const quoted = npxArgs.map((a) => (/^[\w@./:=-]+$/.test(a) ? a : `"${String(a).replace(/"/g, '\\"')}"`));
    res = spawnSync('npx.cmd', quoted, { stdio: 'inherit', shell: true });
  } else {
    res = spawnSync('npx', npxArgs, { stdio: 'inherit' });
  }
  if (res.error) {
    console.error(`zero-hour: could not run npx (${res.error.message}). Install Node.js 18+ with npm, or see the README for git clone install.`);
    return 3;
  }
  return typeof res.status === 'number' ? res.status : 3;
}

// Resolve an executable from PATH only. On Windows, process spawning also searches the
// current directory, so a python.exe planted in the scanned project could otherwise run.
function resolveFromPath(cmd) {
  const path = require('path');
  const fs = require('fs');
  const cwd = fs.realpathSync(process.cwd());
  const exts = IS_WIN ? (process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';') : [''];
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    if (!dir || dir === '.') continue;
    let real;
    try { real = fs.realpathSync(dir); } catch (_) { continue; }
    if (real === cwd) continue;
    for (const ext of exts) {
      const cand = path.join(dir, cmd + ext);
      try { if (fs.statSync(cand).isFile()) return cand; } catch (_) { /* not here */ }
    }
  }
  return null;
}

function findPython() {
  const candidates = [['python3', []], ['python', []]];
  if (IS_WIN) candidates.push(['py', ['-3']]);
  const probe = 'import sys;print(sys.version_info[:2]>=(3,9))';
  for (const [name, pre] of candidates) {
    const cmd = resolveFromPath(name);
    if (!cmd) continue;
    const res = spawnSync(cmd, [...pre, '-c', probe], { encoding: 'utf8', windowsHide: true });
    if (!res.error && res.status === 0 && String(res.stdout).trim() === 'True') {
      return [cmd, pre];
    }
  }
  return null;
}

function runPython(args) {
  if (!fs.existsSync(SCRIPT)) {
    console.error(`zero-hour: missing ${SCRIPT}. Reinstall the package (npx @akshitkhokhani/zero-hour@latest) or clone the repo.`);
    return 3;
  }
  const py = findPython();
  if (!py) {
    console.error(
      'zero-hour: Python 3.9+ was not found (tried python3, python' + (IS_WIN ? ', py -3' : '') + ').\n' +
      '  Install Python 3.9 or newer from https://www.python.org/downloads/ and run this again,\n' +
      '  or use the zero-hour skill inside your AI agent (npx @akshitkhokhani/zero-hour install): the agent can\n' +
      '  run the same checks by hand without Python.'
    );
    return 3;
  }
  const [cmd, pre] = py;
  const res = spawnSync(cmd, [...pre, SCRIPT, ...args], { stdio: 'inherit', windowsHide: false });
  if (res.error) {
    console.error(`zero-hour: failed to start Python (${res.error.message}).`);
    return 3;
  }
  if (res.signal) return 3;
  return typeof res.status === 'number' ? res.status : 3;
}

function main(argv) {
  const first = argv[0];
  if (first === '--help' || first === '-h' || first === 'help') {
    console.log(HELP);
    return 0;
  }
  if (first === '--version' || first === '-v' || first === 'version') {
    console.log(version());
    return 0;
  }
  if (first === 'install') return runInstall(argv.slice(1));
  if (argv.length === 0) return runPython(['scan', '.']);
  return runPython(argv);
}

process.exitCode = main(process.argv.slice(2));
