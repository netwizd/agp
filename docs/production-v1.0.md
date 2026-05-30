# AGP v1.0 Production Runbook

## Scope

v1.0 is a production-ready single-node AGP deployment:

- AGP backend runs as a systemd service;
- PostgreSQL is the production database;
- Nginx is the public TLS reverse proxy and data plane;
- generated Nginx snippets are reviewed and applied manually;
- Docker is not required for runtime or release.

v1.1 is reserved for MFA, invite/password setup links, encrypted sensitive
profile fields and notification workflows.

## Production Baseline

Required hosts and accounts:

- Linux VM or bare-metal host;
- local `agp` system user;
- PostgreSQL database owned by a least-privilege `agp` DB role;
- portal DNS name, for example `enter.company.com`;
- one DNS name per proxied resource;
- valid TLS certificates for portal and resource names.

Recommended filesystem layout:

```text
/usr/local/bin/agp
/usr/local/bin/agpctl
/etc/agp/agp.env
/var/lib/agp/downloads
/var/log/agp
```

## Install

Recommended path on a dedicated Ubuntu 22.04/24.04 host:

```bash
sudo ./install.sh
```

The installer asks for the portal DNS name, PostgreSQL database/user names,
initial administrator credentials, Nginx/TLS choices and `auto` vs `manual`
execution mode. It generates the PostgreSQL application password automatically,
configures PostgreSQL with SCRAM authentication, writes `/etc/agp/agp.env`,
installs systemd units, starts AGP, optionally configures the official
`nginx.org` package repository, requests a Let's Encrypt certificate and enables
the backup timer.

Manual installation steps are kept below for audited deployments or non-standard
infrastructure.

1. Build binaries:

```bash
./scripts/release-check.sh
```

2. Create OS directories:

```bash
sudo useradd --system --home /var/lib/agp --shell /usr/sbin/nologin agp
sudo install -d -o agp -g agp -m 0750 /etc/agp /var/lib/agp /var/lib/agp/downloads /var/log/agp
sudo install -o root -g root -m 0755 bin/agp bin/agpctl /usr/local/bin/
```

3. Create PostgreSQL database:

```sql
CREATE USER agp WITH PASSWORD 'change-me';
CREATE DATABASE agp OWNER agp;
```

4. Configure `/etc/agp/agp.env` from `configs/agp.example.env`.

Minimum production changes:

```bash
AGP_PORTAL_HOST=enter.company.com
AGP_DATABASE_DRIVER=postgres
AGP_DATABASE_DSN=postgres://agp:change-me@127.0.0.1:5432/agp?sslmode=require
AGP_DOWNLOADS_DIR=/var/lib/agp/downloads
AGP_COOKIE_SECURE=true
AGP_TRUST_PROXY_HEADERS=true
AGP_TRUSTED_PROXY_CIDRS=127.0.0.1/32,10.0.0.0/8
AGP_AUDIT_RETENTION=8760h
AGP_SESSION_RETENTION=720h
AGP_DOWNLOAD_ALLOWED_EXTENSIONS=.zip,.rar,.7z,.msi,.exe,.pkg,.dmg,.pdf,.txt,.rdp,.ovpn,.conf
# optional external scanner; {path} is replaced with the temporary upload path
AGP_DOWNLOAD_SCAN_COMMAND=clamscan --no-summary {path}
# optional diagnostics allowlist; if set, every resolved target IP must match it
AGP_DIAGNOSTICS_ALLOW_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
AGP_DIAGNOSTICS_DENY_CIDRS=127.0.0.0/8,::1/128,169.254.0.0/16,fe80::/10,0.0.0.0/8,::/128
```

5. Install systemd unit and Nginx config:

```bash
sudo install -o root -g root -m 0644 deploy/systemd/agp.service /etc/systemd/system/agp.service
sudo systemctl daemon-reload
sudo systemctl enable --now agp
sudo nginx -t
sudo systemctl reload nginx
```

6. Bootstrap first administrator:

```bash
printf '%s\n' "$AGP_ADMIN_PASSWORD" | sudo -u agp /usr/local/bin/agpctl create-admin -username admin
```

## Readiness And Metrics

Local checks:

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/metrics
```

`/healthz` confirms the HTTP process is serving.
`/readyz` confirms the storage backend can be queried.
`/metrics` exports cheap process/storage liveness gauges. Administrative counts
are intentionally kept in the authenticated dashboard so Prometheus scraping does
not run heavy table scans.

Nginx should expose `/healthz` and `/readyz` according to the deployment policy.
`/metrics` should be limited to localhost or monitoring networks.

## Backup

Install backup scripts and timer:

```bash
sudo install -o root -g root -m 0755 scripts/agp-backup.sh scripts/agp-restore.sh /usr/local/bin/
sudo install -o root -g root -m 0644 deploy/systemd/agp-backup.service /etc/systemd/system/agp-backup.service
sudo install -o root -g root -m 0644 deploy/systemd/agp-backup.timer /etc/systemd/system/agp-backup.timer
sudo systemctl daemon-reload
sudo systemctl enable --now agp-backup.timer
```

Manual backup:

```bash
sudo -u agp AGP_BACKUP_DIR=/secure-backups AGP_DATABASE_NAME=agp /usr/local/bin/agp-backup.sh
```

Production requirements:

- encrypt backups before off-host transfer;
- keep backup files and checksum manifests mode `0600`;
- keep backup retention aligned with audit policy;
- test restore monthly;
- monitor backup freshness.

## Restore Drill

```bash
createdb agp_restore
AGP_DOWNLOADS_PARENT=/var/lib/agp /usr/local/bin/agp-restore.sh \
  /secure-backups/agp-db-YYYYMMDDTHHMMSSZ.dump \
  /secure-backups/agp-downloads-YYYYMMDDTHHMMSSZ.tar.gz \
  agp_restore \
  /secure-backups/agp-YYYYMMDDTHHMMSSZ.sha256
```

Run AGP against the restored DB in a maintenance environment and verify:

- `/readyz` returns `ready`;
- admin login works;
- resource list is present;
- public downloads are downloadable;
- audit list is readable.

## Release Checklist

Before tagging v1.0:

```bash
./scripts/release-check.sh
```

`AGP_TEST_POSTGRES_DSN` is mandatory for v1.0 release checks. The script fails
without a live PostgreSQL DSN.

Manual checks:

- `systemctl status agp`;
- `journalctl -u agp -n 100`;
- `nginx -t`;
- portal login/logout;
- admin resource create/edit;
- generated Nginx snippet review;
- protected resource access allowed for authorized user;
- protected resource access denied for unauthorized user;
- `/access-denied` does not reveal whether a guessed resource exists.
