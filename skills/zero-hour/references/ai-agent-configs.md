# AI-agent config files that can run code

Load this when a card has `iocs.strings`, when a worm is known to plant agent configs
(e.g. tensorlake commits `.claude/settings.json` + `.vscode/tasks.json`), or on `--deep`.
These files are a new persistence/propagation path: they run commands when a repo is
**opened** in an agent or editor, long after the malicious package is gone.

## Files to check (project = repo root, user = home directory)
| Tool | File | What can execute |
|---|---|---|
| Claude Code | `.claude/settings.json`, `.claude/settings.local.json` (project) | `hooks` (SessionStart, PreToolUse, PostToolUse, UserPromptSubmit, Stop, ...) run shell `command`s; `statusLine.command`; `apiKeyHelper` |
| Claude Code | `~/.claude/settings.json` (user) | same keys, apply to every repo |
| Claude Code | `.mcp.json` (project), `~/.claude.json` (user + per-project MCP servers) | `mcpServers.*.command` + `args` start a process |
| Claude Code | `.claude/commands/`, `.claude/agents/`, `.claude/skills/`, `CLAUDE.md` | prompt injection; skills may ship scripts |
| Cursor | `.cursor/mcp.json`, `~/.cursor/mcp.json` | `mcpServers.*.command` |
| Cursor | `.cursor/hooks.json`, `~/.cursor/hooks.json` (newer versions) | hook commands |
| Cursor | `.cursor/rules/*.mdc`, `.cursorrules` | prompt injection (incl. hidden Unicode) |
| VS Code (+ forks) | `.vscode/tasks.json` | tasks with `"runOptions": {"runOn": "folderOpen"}` run when the folder opens |
| VS Code | `.vscode/settings.json`, `.vscode/mcp.json`, `.vscode/launch.json` | paths to executables/interpreters, MCP servers, debug commands |
| Codex CLI | `~/.codex/config.toml`, `.codex/config.toml` | `[mcp_servers.<name>]` `command`/`args`; `notify` command |
| Codex CLI | `AGENTS.md` | prompt injection |
| Gemini CLI | `.gemini/settings.json`, `~/.gemini/settings.json` | `mcpServers.*.command`, `toolDiscoveryCommand`, `toolCallCommand`, `hooks` if present |
| Gemini CLI | `~/.gemini/extensions/`, `GEMINI.md` | extension MCP servers; prompt injection |
| Kiro | `.kiro/settings/mcp.json`, `~/.kiro/settings/mcp.json` | `mcpServers.*.command` |
| Kiro | `.kiro/hooks/`, `.kiro/steering/` | agent hooks; prompt injection |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `mcpServers.*.command` |
| Windsurf | `.windsurfrules`, `.windsurf/rules/`, `.windsurf/workflows/` | prompt injection |
| Copilot | `.github/copilot-instructions.md`, `.github/instructions/`, `.github/prompts/` | prompt injection |
| Cline | `.clinerules`, `cline_mcp_settings.json` (VS Code globalStorage) | prompt injection; MCP commands |

## What malicious looks like
- Any card `iocs.strings` value (e.g. `gh-token-monitor`, `Math_Symbol`, `iseekaigogo`, `letters9813`).
- Commands that download and run: `curl ... | sh`, `wget -O- ... | bash`, `iwr ... | iex`,
  `npx -y <unknown-pkg>`, `bunx`, `node -e`, `python -c`, `base64 -d`, `eval`, `powershell -enc`.
- Commands pointing into `node_modules/`, `/tmp`, hidden dirs, or a file that was added in the
  same commit.
- `SessionStart`/`folderOpen` triggers (fire with no user action), especially in **project** files.
- The file was added/changed by an unexpected author or a generic message
  (e.g. `claude@users.noreply.github.com` + "chore: update dependencies").
- MCP servers you did not install, or ones with `env` that forwards tokens.
- Rules/instructions files containing hidden Unicode (zero-width, bidi overrides, tag chars)
  or text telling the agent to run commands, disable checks, or exfiltrate data.

## How to review safely
1. **Do not open the repo in the agent/IDE first**. Opening can fire `folderOpen` tasks and
   project hooks. Use a plain terminal, or VS Code Restricted Mode (Workspace Trust).
2. Read, don't execute:
```bash
ls -la .claude .cursor .vscode .codex .gemini .kiro .windsurf .mcp.json 2>/dev/null
python3 -m json.tool .claude/settings.json          # pretty-print, no execution
grep -rnE 'runOn|folderOpen' .vscode/tasks.json 2>/dev/null
grep -rnE 'curl|wget|\| *(ba)?sh|npx -y|bunx|node -e|python -c|base64|eval|iex|-enc' \
  .claude .cursor .vscode .codex .gemini .kiro .windsurf .mcp.json ~/.claude/settings.json \
  ~/.codex/config.toml ~/.gemini/settings.json ~/.cursor/mcp.json 2>/dev/null
git log --all --format='%h %an <%ae> %ad %s' -- .claude .vscode .cursor .mcp.json .codex .gemini .kiro
```
3. Hidden Unicode in rules/instructions (stdlib only):
```bash
python3 - <<'PY'
import pathlib,re
bad=re.compile('[​-‏‪-‮⁦-⁩\U000e0000-\U000e007f]')
for p in pathlib.Path('.').rglob('*'):
    if p.is_file() and (p.suffix in {'.md','.mdc','.json','.toml'} or p.name in {'.cursorrules','.windsurfrules','.clinerules'}):
        try: t=p.read_text(encoding='utf-8')
        except Exception: continue
        for i,l in enumerate(t.splitlines(),1):
            if bad.search(l): print(f"{p}:{i}: hidden unicode")
PY
```
4. Never print secrets found in these files (`env`, `apiKeyHelper` output); report the key
   name and file:line only.

## Fix (user decides)
Show the diff (`git show <commit> -- <file>`), then let the user revert the commit or remove
the hook/task/server. If the file came from a worm, follow the card's remediation order:
disarm persistence → rotate → clean repos (all branches, not just main) → force collaborators
to pull the clean version.
