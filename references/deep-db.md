# Deep check: database exposure (READ-ONLY)

Load on `--deep` or when an incident involves stolen DB credentials. Never attempt logins with
guessed passwords, never write, never dump data. Report key names and `file:line`, never values.

## 1. Listening on all interfaces?
```bash
lsof -nP -iTCP -sTCP:LISTEN | grep -E ':(5432|3306|1433|1521|6379|27017|9200|9300|5984|11211|8086)\b'   # macOS/Linux
ss -ltnp | grep -E ':(5432|3306|1433|6379|27017|9200)\b'                                           # Linux
docker ps --format '{{.Names}}\t{{.Ports}}' | grep -E '0\.0\.0\.0:|:::'                              # published to all IPs
grep -rnE '^\s*-\s*"?[0-9]+:[0-9]+' docker-compose*.y*ml compose*.y*ml 2>/dev/null                  # "5432:5432" = all interfaces
```
```powershell
Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 5432,3306,1433,6379,27017,9200 | Select-Object LocalAddress,LocalPort,OwningProcess
```
`0.0.0.0` / `::` / `*` = reachable from the network (and Docker bypasses ufw/firewalld rules on
Linux). Safer: `127.0.0.1:5432:5432` or no published port at all.

## 2. Auth and defaults (read config files only)
| Engine | Look for | File |
|---|---|---|
| PostgreSQL | `listen_addresses = '*'`; `trust` method in `pg_hba.conf`; `host all all 0.0.0.0/0` | `postgresql.conf`, `pg_hba.conf` |
| MySQL/MariaDB | `bind-address = 0.0.0.0`; empty `MYSQL_ROOT_PASSWORD`, `MYSQL_ALLOW_EMPTY_PASSWORD=yes` | `my.cnf`, compose env |
| Redis | `protected-mode no`; no `requirepass` / ACL; `bind 0.0.0.0` | `redis.conf` |
| MongoDB | `bindIp: 0.0.0.0` without `security.authorization: enabled` | `mongod.conf` |
| Elasticsearch/OpenSearch | `xpack.security.enabled: false` / security plugin disabled | `elasticsearch.yml`, compose env |
| Any | default/sample passwords in compose/.env (`postgres`, `root`, `password`, `changeme`) | `docker-compose*.yml`, `.env*` |

## 3. TLS
- Connection strings with `sslmode=disable` / `ssl=false` / `tls=false` for non-local hosts.
- PostgreSQL `ssl = off`; MySQL `require_secure_transport = OFF`; managed DB "require SSL" off:
  `gcloud sql instances describe <i> --format='value(settings.ipConfiguration.sslMode,settings.ipConfiguration.requireSsl)'`.

## 4. Managed DBs and snapshots (only if the cloud CLI is already authenticated)
```bash
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,PubliclyAccessible,StorageEncrypted]'
aws rds describe-db-snapshots --snapshot-type manual --query 'DBSnapshots[].DBSnapshotIdentifier'
aws rds describe-db-snapshot-attributes --db-snapshot-identifier <id>       # "restore" containing "all" = public
gcloud sql instances list --format=json | grep -A3 authorizedNetworks       # 0.0.0.0/0 = open
az postgres flexible-server list --query "[].{n:name,public:network.publicNetworkAccess}"
```

## 5. Connection strings / credentials in the repo
```bash
grep -rnE '(postgres(ql)?|mysql|mariadb|mongodb(\+srv)?|redis|rediss|amqp)://[^:/ ]+:[^@ ]+@' \
  --exclude-dir={node_modules,.git,vendor,.venv} . | sed -E 's#://([^:]+):[^@]+@#://\1:[redacted]@#'
git log -p --all -S 'postgres://' | grep -nE '^\+.*://[^:]+:[^@]+@' | sed -E 's#:[^:@/]+@#:[redacted]@#' | head
git check-ignore -q .env || echo ".env is NOT gitignored"
```
If `gitleaks` or `trufflehog` is installed, prefer them (`gitleaks detect --redact`).
A credential found in git history is compromised even if deleted later: plan rotation
(see `fix-planning.md`), then history cleanup is the user's decision.

## Report
Top findings only: exposure (network-reachable + weak/no auth) first, then TLS, then hygiene.
Fixes as instructions: bind to localhost/private network, require auth + TLS, close public
access, rotate exposed credentials, move secrets to a secret manager.
