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
`/metrics` exports basic Prometheus-style gauges.

Nginx should expose `/healthz` and `/readyz` according to the deployment policy.
`/metrics` should be limited to localhost or monitoring networks.

## Backup

PostgreSQL minimum:

```bash
pg_dump --format=custom --file=/secure-backups/agp-$(date +%F).dump agp
```

Downloads directory:

```bash
tar -C /var/lib/agp -czf /secure-backups/agp-downloads-$(date +%F).tar.gz downloads
```

Production requirements:

- encrypt backups before off-host transfer;
- keep backup retention aligned with audit policy;
- test restore monthly;
- monitor backup freshness.

## Restore Drill

```bash
createdb agp_restore
pg_restore --dbname=agp_restore /secure-backups/agp-YYYY-MM-DD.dump
tar -C /var/lib/agp -xzf /secure-backups/agp-downloads-YYYY-MM-DD.tar.gz
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

If a disposable PostgreSQL database is available:

```bash
AGP_TEST_POSTGRES_DSN='postgres://agp:change-me@127.0.0.1:5432/agp?sslmode=require' \
  ./scripts/release-check.sh
```

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
