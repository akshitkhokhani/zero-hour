# Deep check: cloud posture (READ-ONLY)

Load on `--deep`. Only use a cloud CLI that is **already authenticated** (`aws sts get-caller-identity`,
`gcloud config list account`, `az account show`). Never log in for the user, never run
create/put/update/delete/modify/attach/set commands. Report at most the **top 10** findings,
ranked by how exploitable they are (internet-exposed + sensitive > credential hygiene > logging).
If a check needs more permission than the user has, mark it UNKNOWN. Never print secrets.

## AWS (CIS AWS Foundations Benchmark; ids per v3.0)
| Check | Read-only command | CIS |
|---|---|---|
| Root has MFA | `aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'` (1 = on) | 1.5 |
| No root access keys | `aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'` (0 = good) | 1.4 |
| Old / unused access keys | `aws iam get-credential-report --query Content --output text \| base64 -d` (read the header for `access_key_*_last_rotated` / `_last_used_date`; needs a report to exist; `generate-credential-report` creates one, so ask first) | 1.12, 1.14 |
| Full-admin `*:*` customer policies | `aws iam list-policies --scope Local --only-attached --query 'Policies[].[PolicyName,Arn,DefaultVersionId]'` then `aws iam get-policy-version --policy-arn <arn> --version-id <v>` | 1.16 |
| CloudTrail on in all regions | `aws cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail]'` + `aws cloudtrail get-trail-status --name <trail> --query IsLogging` | 3.1 |
| S3 public access blocked (account) | `aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text)` | (S3 section) |
| Public buckets | `aws s3api list-buckets --query 'Buckets[].Name'` then per bucket `aws s3api get-bucket-policy-status --bucket <b> --query PolicyStatus.IsPublic` | (S3 section) |
| SGs open to the world on admin/DB ports | `aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0 --query 'SecurityGroups[].[GroupId,GroupName,IpPermissions[].[FromPort,ToPort]]'` (repeat per region; flag 22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, all-ports) | 5.2 (22/3389) |
| Public RDS / snapshots | see `deep-db.md` | |

## GCP (CIS GCP Foundations Benchmark)
| Check | Read-only command | CIS |
|---|---|---|
| Firewall open to 0.0.0.0/0 | `gcloud compute firewall-rules list --filter='direction=INGRESS AND sourceRanges:0.0.0.0/0' --format=json` (flag 22, 3389, DB ports) | 3.6 (SSH), 3.7 (RDP) |
| Public buckets | `gcloud storage buckets list --format='value(name)'` then `gcloud storage buckets get-iam-policy gs://<b> --format=json \| grep -E 'allUsers\|allAuthenticatedUsers'` | 5.1 |
| User-managed SA keys | `gcloud iam service-accounts list --format='value(email)'` then `gcloud iam service-accounts keys list --iam-account=<sa> --managed-by=user` | |
| Primitive roles / public principals | `gcloud projects get-iam-policy <project> --format=json` (look for `roles/owner`, `roles/editor`, `allUsers`) | |

## Azure
| Check | Read-only command |
|---|---|
| NSG rules open to Internet | `az network nsg list --query "[].{nsg:name,rules:securityRules[?access=='Allow' && direction=='Inbound' && (sourceAddressPrefix=='*' \|\| sourceAddressPrefix=='0.0.0.0/0' \|\| sourceAddressPrefix=='Internet')].[name,destinationPortRange]}"` |
| Storage public blob access / TLS / HTTPS-only | `az storage account list --query "[].{n:name,publicBlob:allowBlobPublicAccess,minTls:minimumTlsVersion,https:enableHttpsTrafficOnly}"` |
| Defender plans | `az security pricing list --query "value[].{n:name,tier:pricingTier}"` |
| Owner role assignments | `az role assignment list --all --role Owner --query "[].principalName"` |
(Azure CIS ids omitted on purpose: they shift between benchmark versions.)

## Report
Each finding: resource id, why it matters in one line, CIS id if listed above, and the fix as an
**instruction** (console path or CLI command for the user to run). No mutations. If an incident
is active (e.g. credential theft), first check audit logs for use of the stolen identity:
`aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<key-id> --start-time <date>`.
