# IOC hunting (read-only)

Load this when a card has `iocs` or the user asks "was I actually infected?".
Everything here only **reads**. Removal is a separate step the user approves.

## Golden rule: dead-man switches before revocation
Some malware watches the token it stole and destroys data when the token stops working
(e.g. tensorlake `gh-token-monitor` deletes the home directory once the GitHub token is revoked).
Before telling anyone to revoke, rotate or log out:
1. Search for persistence below (and the card's `iocs.files`).
2. If found: back up, unload/disable it, confirm the process is gone, THEN rotate.
3. Rotate from a clean machine if the host is compromised.

## Do not tip off the attacker
Never `curl`, `ping`, `dig` or open IOC domains/URLs. Search logs for them instead.

## macOS
```bash
ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons
launchctl list | grep -v com.apple                  # loaded jobs (user)
launchctl print gui/$(id -u)/<label>                # one job: program, args, state
plutil -p ~/Library/LaunchAgents/<file>.plist       # read a plist
sudo sfltool dumpbtm | less                         # login items + background tasks (macOS 13+)
crontab -l; ls -la /etc/periodic/daily 2>/dev/null
grep -nE 'curl|wget|base64|eval|bun |node -e|python -c' ~/.zshrc ~/.zprofile ~/.bash_profile ~/.profile 2>/dev/null
```

## Linux
```bash
systemctl --user list-unit-files --state=enabled; ls -la ~/.config/systemd/user
systemctl list-unit-files --state=enabled | grep -v '@'; ls -la /etc/systemd/system
systemctl --user list-timers --all; systemctl list-timers --all
systemctl --user status <unit>                      # what it runs
crontab -l; ls -la /etc/cron.* /var/spool/cron 2>/dev/null
ls -la ~/.config/autostart 2>/dev/null; cat /etc/ld.so.preload 2>/dev/null
grep -nE 'curl|wget|base64|eval|bun |node -e|python -c' ~/.bashrc ~/.profile ~/.bash_profile ~/.zshrc /etc/profile.d/* 2>/dev/null
```

## Windows (PowerShell)
```powershell
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | Select-Object TaskName,TaskPath,State
Get-ScheduledTask | Where-Object { ($_.Actions | Out-String) -match '<ioc>' }   # e.g. monitor.ps1
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location
Get-Content $PROFILE -ErrorAction SilentlyContinue
```

## Python start-up hooks (.pth / sitecustomize)
`site.py` executes any line starting with `import` in every `*.pth` file in site-packages,
at **every** interpreter start, even if the malicious package is never imported. It also
imports `sitecustomize.py` and `usercustomize.py`. Inspect without triggering them:
```bash
python3 -S -c "import site; print('\n'.join(site.getsitepackages() + [site.getusersitepackages()]))"
grep -l '^import' <site-packages>/*.pth            # which .pth files execute code
ls -la <site-packages>/sitecustomize.py <site-packages>/usercustomize.py 2>/dev/null
```
`-S` skips site processing, so the hook does not run. Usually legitimate: `distutils-precedence.pth`
(setuptools), `_virtualenv.pth`, `__editable__.*.pth`. Anything else with `import`, `exec`,
base64 or network calls is suspect. Check every venv (`.venv`, `venv`, conda envs, pipx, uv tools).

## npm / JS lifecycle scripts
`preinstall`, `install`, `postinstall`, `prepare` run on install (pnpm 10+ and bun block
dependency scripts by default; npm and yarn classic run them).
```bash
npm query ':attr(scripts, [preinstall])' | grep -E '"name"|"preinstall"'
npm query ':attr(scripts, [postinstall])' | grep -E '"name"|"postinstall"'
grep -lE '"(pre|post)?install"' node_modules/*/package.json node_modules/@*/*/package.json 2>/dev/null
```
Hash a suspect file against card `sha256`: `shasum -a 256 <f>` (macOS), `sha256sum <f>` (Linux),
`Get-FileHash <f> -Algorithm SHA256` (Windows).

## Network IOCs (egress)
```bash
lsof -i -nP | grep ESTABLISHED          # macOS/Linux: live connections + process
ss -tunp                                # Linux
netstat -an | grep ESTABLISHED          # any OS
grep -i '<domain>' /etc/hosts
```
```powershell
Get-NetTCPConnection -State Established | Select-Object RemoteAddress,RemotePort,OwningProcess
Get-DnsClientCache | Where-Object Entry -match '<domain>'
```
Live connections only show "now". For history, search DNS/proxy/firewall logs: corporate DNS,
Pi-hole, cloud resolver logs (AWS Route 53 Resolver query logs, GCP Cloud DNS logging),
EDR telemetry, CI runner logs. No log access → report UNKNOWN, not CLEAR.

## Git / GitHub spread
```bash
git log --all --author='<fake-author-email>' --format='%h %ad %an <%ae> %s'
git log --all --format='%h %an %s' -- .claude/settings.json .vscode/tasks.json .mcp.json
gh repo list --visibility public --limit 500 --json name,description,createdAt
gh search commits --author-email '<fake-author-email>' --owner '<you-or-org>'
```
Then check agent config files with `ai-agent-configs.md`.

## Report format
For each IOC: path or command, what was found (never print secret values), `level`
(`compromised` = proof; `review` = suspicious, may be legit). Nothing found ≠ clean: say what
was checked and what could not be checked.
