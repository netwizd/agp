# AGP - Auth Gateway Portal

AGP is a centralized access gateway for internal corporate resources.

The first implementation target is a single-node deployment:

- Go backend with secure session-based authentication.
- PostgreSQL as the production storage backend.
- SQLite as an optional development/small-install fallback.
- Nginx as the public TLS reverse proxy using `auth_request`.
- Admin API for users, groups, resources, public downloads, portal settings, sessions, audit and Nginx recommendations.
- Permission-based RBAC with `is_admin` superuser compatibility.
- Embedded static frontend shell for login, public downloads, portal and admin basics.
- Audit-first access model for authentication, resource access and denied requests.

## Repository Layout

```text
cmd/agp/                  Application entrypoint
internal/auth/            Password hashing and session token primitives
internal/config/          Runtime configuration from environment
internal/domain/          Core domain models
internal/httpapi/         HTTP API and nginx auth_request contract
internal/reverseproxy/    Safe reverse proxy recommendation generators
internal/storage/         Storage interfaces
internal/storage/postgres/PostgreSQL implementation and migrations
internal/storage/sqlite/  SQLite implementation and migrations
configs/                  Example runtime configuration
deploy/                   Nginx, systemd, Docker and logrotate templates
docs/                     Architecture, security and operations notes
```

## Local Run

Install Go 1.22+ and prepare PostgreSQL:

```sql
CREATE USER agp WITH PASSWORD 'change-me';
CREATE DATABASE agp OWNER agp;
```

Then run:

```bash
cp configs/agp.example.env .env
go mod download
set -a && . ./.env && set +a
go run ./cmd/agp
```

By default the backend listens on `127.0.0.1:8080` and expects PostgreSQL at
`127.0.0.1:5432`. For local fallback set `AGP_DATABASE_DRIVER=sqlite`.

Create the first administrator:

```bash
printf '%s\n' "$AGP_ADMIN_PASSWORD" | go run ./cmd/agpctl create-admin
```

See [docs/implementation-snapshot.md](docs/implementation-snapshot.md) for the
current implementation status and [docs/roadmap.md](docs/roadmap.md) for the
check-up and roadmap.

For production v1.0 deployment, use the interactive Ubuntu installer:

```bash
sudo ./install.sh
```

The installer supports `auto` and `manual` modes. It asks for the minimum
deployment inputs, generates the PostgreSQL application password, configures the
local PostgreSQL role/database, installs official `nginx.org` Nginx when
requested, installs `certbot` only when Let's Encrypt automation is requested,
writes `/etc/agp/agp.env`, installs systemd units and can enable the backup
timer.

```bash
sudo ./install.sh --manual
sudo ./install.sh --auto
```

The detailed manual runbook is in
[docs/production-v1.0.md](docs/production-v1.0.md). v1.1 identity and
notification work is tracked in [docs/v1.1-plan.md](docs/v1.1-plan.md).

## Security Posture

AGP is a security boundary. Production deployments must keep the backend bound
to localhost or a private interface and expose it only through Nginx with TLS,
strict proxy headers, access logs and `auth_request`.
