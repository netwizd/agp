#!/usr/bin/env bash
set -Eeuo pipefail

AGP_REPO_URL="${AGP_REPO_URL:-https://github.com/netwizd/agp.git}"
GO_VERSION_DEFAULT="${GO_VERSION_DEFAULT:-1.22.12}"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/agp-src}"
ORIGINAL_ARGS=("$@")

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR"
if [[ ! -f "$SOURCE_DIR/go.mod" ]]; then
  SOURCE_DIR="$INSTALL_ROOT"
fi

MODE="manual"
PORTAL_HOST=""
LE_EMAIL=""
SETUP_CERTBOT="yes"
SETUP_BACKUPS="yes"
SETUP_NGINX="yes"
POSTGRES_MODE="local"
POSTGRES_HBA_MODE="managed"
DB_NAME="agp"
DB_USER="agp"
DB_PASSWORD=""
ADMIN_USER="admin"
ADMIN_PASSWORD=""
GENERATED_ADMIN_PASSWORD="no"

log() {
  printf '\n[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"
}

warn() {
  printf '\n[WARN] %s\n' "$*" >&2
}

die() {
  printf '\n[ERROR] %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  ./install.sh
  ./install.sh --auto
  ./install.sh --manual

Environment overrides:
  AGP_REPO_URL=https://github.com/netwizd/agp.git
  GO_VERSION_DEFAULT=1.22.12
  INSTALL_ROOT=/opt/agp-src

The installer is intended for Ubuntu 22.04/24.04 production-style single-node
deployment without Docker.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auto)
      MODE="auto"
      shift
      ;;
    --manual)
      MODE="manual"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  log "Re-running installer through sudo."
  exec sudo -E bash "$0" "${ORIGINAL_ARGS[@]}"
fi

ask() {
  local prompt="$1"
  local default_value="${2:-}"
  local value
  if [[ -n "$default_value" ]]; then
    read -r -p "$prompt [$default_value]: " value
    printf '%s' "${value:-$default_value}"
  else
    read -r -p "$prompt: " value
    printf '%s' "$value"
  fi
}

ask_secret() {
  local prompt="$1"
  local value
  read -r -s -p "$prompt: " value
  printf '\n' >&2
  printf '%s' "$value"
}

ask_yes_no() {
  local prompt="$1"
  local default_value="${2:-yes}"
  local value
  while true; do
    read -r -p "$prompt [$default_value]: " value
    value="${value:-$default_value}"
    case "${value,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) printf 'Please answer yes or no.\n' ;;
    esac
  done
}

ask_mode() {
  local prompt="$1"
  local default_value="${2:-manual}"
  local value
  while true; do
    read -r -p "$prompt [$default_value]: " value
    value="${value:-$default_value}"
    case "${value,,}" in
      auto|a) printf 'auto'; return 0 ;;
      manual|m) printf 'manual'; return 0 ;;
      *) printf 'Please answer auto or manual.\n' ;;
    esac
  done
}

pause_for_manual_step() {
  local title="$1"
  if [[ "$MODE" == "manual" ]]; then
    printf '\n--- %s ---\n' "$title"
    if ! ask_yes_no "Run this step now?" "yes"; then
      die "stopped before step: $title"
    fi
  else
    log "$title"
  fi
}

run_step() {
  local title="$1"
  shift
  pause_for_manual_step "$title"
  "$@"
}

require_ubuntu() {
  [[ -r /etc/os-release ]] || die "/etc/os-release not found"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "this installer supports Ubuntu only; detected ID=${ID:-unknown}"
  case "${VERSION_ID:-}" in
    22.04|24.04) ;;
    *) warn "Ubuntu ${VERSION_ID:-unknown} is not the primary tested target. Continuing." ;;
  esac
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

collect_answers() {
  log "AGP installer questions"
  PORTAL_HOST="$(ask "Portal DNS name" "${AGP_PORTAL_HOST:-enter.company.com}")"
  [[ -n "$PORTAL_HOST" ]] || die "portal host is required"

  DB_NAME="$(ask "PostgreSQL database name" "${AGP_DB_NAME:-agp}")"
  DB_USER="$(ask "PostgreSQL application user" "${AGP_DB_USER:-agp}")"
  DB_PASSWORD="${AGP_DB_PASSWORD:-$(openssl rand -hex 32)}"
  printf 'Generated PostgreSQL password for user %s.\n' "$DB_USER"

  ADMIN_USER="$(ask "Initial AGP admin username" "${AGP_ADMIN_USER:-admin}")"
  ADMIN_PASSWORD="$(ask_secret "Initial AGP admin password (leave empty to generate)")"
  if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD="$(openssl rand -hex 18)"
    GENERATED_ADMIN_PASSWORD="yes"
  fi
  if (( ${#ADMIN_PASSWORD} < 12 )); then
    die "admin password must be at least 12 characters"
  fi

  if ask_yes_no "Install and configure official nginx.org Nginx?" "yes"; then
    SETUP_NGINX="yes"
  else
    SETUP_NGINX="no"
  fi

  if [[ "$SETUP_NGINX" == "yes" ]] && ask_yes_no "Request Let's Encrypt certificate with certbot?" "yes"; then
    SETUP_CERTBOT="yes"
    LE_EMAIL="$(ask "Let's Encrypt notification email" "${LE_EMAIL:-admin@$PORTAL_HOST}")"
  else
    SETUP_CERTBOT="no"
  fi

  if ask_yes_no "Install AGP backup timer?" "yes"; then
    SETUP_BACKUPS="yes"
  else
    SETUP_BACKUPS="no"
  fi

  MODE="$(ask_mode "Installation mode: auto or manual" "$MODE")"

  if ask_yes_no "Replace pg_hba.conf with AGP-only local PostgreSQL policy? Recommended on a dedicated AGP host." "yes"; then
    POSTGRES_HBA_MODE="managed"
  else
    POSTGRES_HBA_MODE="preserve"
  fi
}

print_summary() {
  cat <<EOF

Installation summary:
  mode:                  $MODE
  source dir:            $SOURCE_DIR
  portal host:           $PORTAL_HOST
  nginx setup:           $SETUP_NGINX
  certbot setup:         $SETUP_CERTBOT
  postgres mode:         $POSTGRES_MODE
  postgres hba mode:     $POSTGRES_HBA_MODE
  db name:               $DB_NAME
  db user:               $DB_USER
  agp admin user:        $ADMIN_USER
  backups:               $SETUP_BACKUPS

Files:
  /usr/local/bin/agp
  /usr/local/bin/agpctl
  /etc/agp/agp.env
  /etc/systemd/system/agp.service
  /etc/nginx/conf.d/agp-portal.conf

EOF
  ask_yes_no "Continue installation?" "yes" || die "installation cancelled"
}

install_base_packages() {
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git curl ca-certificates gnupg2 lsb-release ubuntu-keyring \
    build-essential openssl \
    postgresql postgresql-client postgresql-contrib \
    logrotate ufw
}

install_go_if_needed() {
  local need_go_install="no"
  local current_go=""
  if ! command -v go >/dev/null 2>&1; then
    need_go_install="yes"
  else
    current_go="$(go version | awk '{print $3}' | sed 's/^go//')"
    if ! dpkg --compare-versions "$current_go" ge "1.22"; then
      need_go_install="yes"
    fi
  fi

  if [[ "$need_go_install" == "no" ]]; then
    log "Go is already installed: $(go version)"
    return
  fi

  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "unsupported architecture for Go tarball: $(uname -m)" ;;
  esac

  local go_version="${GO_VERSION:-$GO_VERSION_DEFAULT}"
  local archive="go${go_version}.linux-${arch}.tar.gz"
  log "Installing Go ${go_version} for ${arch}"
  curl -fL "https://go.dev/dl/${archive}" -o "/tmp/${archive}"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/${archive}"
  cat >/etc/profile.d/go.sh <<'EOF'
export PATH=/usr/local/go/bin:$PATH
EOF
  export PATH="/usr/local/go/bin:$PATH"
  go version
}

install_nginx_org() {
  [[ "$SETUP_NGINX" == "yes" ]] || return

  curl -fsSL https://nginx.org/keys/nginx_signing.key \
    | gpg --dearmor \
    >/usr/share/keyrings/nginx-archive-keyring.gpg

  local codename
  codename="$(lsb_release -cs)"
  cat >/etc/apt/sources.list.d/nginx.list <<EOF
deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/ubuntu ${codename} nginx
EOF

  cat >/etc/apt/preferences.d/99nginx <<'EOF'
Package: *
Pin: origin nginx.org
Pin: release o=nginx
Pin-Priority: 900
EOF

  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
  systemctl enable --now nginx
  nginx -v
}

install_certbot_if_enabled() {
  [[ "$SETUP_CERTBOT" == "yes" ]] || return
  DEBIAN_FRONTEND=noninteractive apt-get install -y certbot python3-certbot-nginx
  certbot --version
}

configure_postgres() {
  systemctl enable --now postgresql
  require_command psql

  local pg_conf pg_hba
  pg_conf="$(runuser -u postgres -- psql -tAc 'SHOW config_file;' | xargs)"
  pg_hba="$(runuser -u postgres -- psql -tAc 'SHOW hba_file;' | xargs)"
  [[ -n "$pg_conf" && -f "$pg_conf" ]] || die "postgresql.conf not found"
  [[ -n "$pg_hba" && -f "$pg_hba" ]] || die "pg_hba.conf not found"

  cp "$pg_conf" "$pg_conf.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  cp "$pg_hba" "$pg_hba.bak.$(date -u +%Y%m%dT%H%M%SZ)"

  runuser -u postgres -- psql -v ON_ERROR_STOP=1 <<'SQL'
ALTER SYSTEM SET listen_addresses = '127.0.0.1';
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
SQL

  if [[ "$POSTGRES_HBA_MODE" == "managed" ]]; then
    cat >"$pg_hba" <<EOF
# AGP managed PostgreSQL client authentication policy.
# Previous file was backed up before installer changes.

local   all       postgres                  peer
host    ${DB_NAME} ${DB_USER} 127.0.0.1/32  scram-sha-256
host    ${DB_NAME} ${DB_USER} ::1/128       scram-sha-256

host    all       all       0.0.0.0/0       reject
host    all       all       ::/0            reject
EOF
  else
    if ! grep -q "AGP managed local application access" "$pg_hba"; then
      {
        printf '\n# AGP managed local application access\n'
        printf 'host    %s    %s    127.0.0.1/32    scram-sha-256\n' "$DB_NAME" "$DB_USER"
        printf 'host    %s    %s    ::1/128         scram-sha-256\n' "$DB_NAME" "$DB_USER"
      } >>"$pg_hba"
    fi
  fi

  systemctl restart postgresql
  systemctl is-active --quiet postgresql
}

create_postgres_database() {
  runuser -u postgres -- psql -v ON_ERROR_STOP=1 \
    -v db_user="$DB_USER" \
    -v db_name="$DB_NAME" \
    -v db_password="$DB_PASSWORD" <<'SQL'
SELECT format(
  'CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION',
  :'db_user',
  :'db_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'db_user')\gexec

ALTER ROLE :"db_user" WITH
  LOGIN
  PASSWORD :'db_password'
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION;

SELECT format('CREATE DATABASE %I OWNER %I', :'db_name', :'db_user')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'db_name')\gexec
SQL

  runuser -u postgres -- psql -v ON_ERROR_STOP=1 \
    -d "$DB_NAME" \
    -v db_user="$DB_USER" \
    -v db_name="$DB_NAME" <<'SQL'
ALTER DATABASE :"db_name" OWNER TO :"db_user";
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db_name" TO :"db_user";
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO :"db_user";
ALTER SCHEMA public OWNER TO :"db_user";
SQL

  PGPASSWORD="$DB_PASSWORD" psql \
    -h 127.0.0.1 \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    -v ON_ERROR_STOP=1 \
    -c 'select current_user, current_database();'
}

prepare_source_tree() {
  if [[ -f "$SOURCE_DIR/go.mod" ]]; then
    log "Using source tree: $SOURCE_DIR"
    return
  fi

  install -d -m 0755 "$(dirname "$INSTALL_ROOT")"
  if [[ -d "$INSTALL_ROOT/.git" ]]; then
    git -C "$INSTALL_ROOT" pull --ff-only
  else
    git clone "$AGP_REPO_URL" "$INSTALL_ROOT"
  fi
  SOURCE_DIR="$INSTALL_ROOT"
}

build_and_install_agp() {
  export PATH="/usr/local/go/bin:$PATH"
  cd "$SOURCE_DIR"
  go test ./...
  go vet ./...

  local version commit built_at ldflags
  version="${AGP_VERSION:-$(cat VERSION 2>/dev/null || echo v1.0.0-dev)}"
  commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  ldflags="-X github.com/netwizd/agp/internal/version.Version=${version} -X github.com/netwizd/agp/internal/version.Commit=${commit} -X github.com/netwizd/agp/internal/version.BuiltAt=${built_at}"

  go build -trimpath -ldflags "$ldflags" -o bin/agp ./cmd/agp
  go build -trimpath -ldflags "$ldflags" -o bin/agpctl ./cmd/agpctl

  install -o root -g root -m 0755 bin/agp /usr/local/bin/agp
  install -o root -g root -m 0755 bin/agpctl /usr/local/bin/agpctl
}

create_agp_user_and_dirs() {
  if ! id agp >/dev/null 2>&1; then
    useradd --system --home /var/lib/agp --shell /usr/sbin/nologin agp
  fi
  install -d -o root -g agp -m 0750 /etc/agp
  install -d -o agp -g agp -m 0750 /var/lib/agp
  install -d -o agp -g agp -m 0750 /var/lib/agp/downloads
  install -d -o agp -g agp -m 0750 /var/log/agp
}

write_agp_env() {
  local env_file="/etc/agp/agp.env"
  if [[ -f "$env_file" ]]; then
    cp "$env_file" "$env_file.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  fi

  cat >"$env_file" <<EOF
AGP_HTTP_ADDR=127.0.0.1:8080
AGP_PORTAL_HOST=${PORTAL_HOST}

AGP_DATABASE_DRIVER=postgres
AGP_DATABASE_DSN=postgres://${DB_USER}:${DB_PASSWORD}@127.0.0.1:5432/${DB_NAME}?sslmode=disable

AGP_DOWNLOADS_DIR=/var/lib/agp/downloads
AGP_DOWNLOAD_MAX_BYTES=268435456

AGP_SESSION_COOKIE_NAME=agp_session
AGP_CSRF_COOKIE_NAME=agp_csrf
AGP_COOKIE_SECURE=true

AGP_TRUST_PROXY_HEADERS=true
AGP_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128

AGP_SESSION_TTL=8h
AGP_SESSION_RETENTION=720h
AGP_AUDIT_RETENTION=8760h
AGP_SHUTDOWN_TIMEOUT=10s

AGP_LOGIN_RATE_LIMIT_MAX=5
AGP_LOGIN_RATE_LIMIT_WINDOW=1m

AGP_DOWNLOAD_ALLOWED_EXTENSIONS=.zip,.msi,.exe,.pkg,.dmg,.pdf,.txt,.rdp,.ovpn,.conf
AGP_DOWNLOAD_SCAN_COMMAND=
AGP_DOWNLOAD_SCAN_TIMEOUT=30s

AGP_DIAGNOSTICS_ALLOW_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
AGP_DIAGNOSTICS_DENY_CIDRS=127.0.0.0/8,::1/128,169.254.0.0/16,fe80::/10,0.0.0.0/8,::/128
AGP_DIAGNOSTICS_RATE_LIMIT_MAX=30
AGP_DIAGNOSTICS_RATE_LIMIT_WINDOW=1m
EOF
  chown root:agp "$env_file"
  chmod 0640 "$env_file"
  runuser -u agp -- test -r "$env_file"
}

show_agp_diagnostics() {
  warn "AGP did not become ready. Diagnostics:"
  systemctl status agp --no-pager || true
  journalctl -u agp -n 120 --no-pager || true
  ss -ltnp 2>/dev/null | grep ':8080' || true
  printf '\nAGP environment file state:\n' >&2
  ls -lah /etc/agp/agp.env >&2 || true
  runuser -u agp -- test -r /etc/agp/agp.env && printf 'agp user can read /etc/agp/agp.env\n' >&2 || true
}

wait_for_agp_ready() {
  local attempts="${1:-30}"
  local delay="${2:-1}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS http://127.0.0.1:8080/readyz >/tmp/agp-readyz.out 2>/tmp/agp-readyz.err; then
      cat /tmp/agp-readyz.out
      rm -f /tmp/agp-readyz.out /tmp/agp-readyz.err
      return 0
    fi
    if ! systemctl is-active --quiet agp; then
      show_agp_diagnostics
      rm -f /tmp/agp-readyz.out /tmp/agp-readyz.err
      return 1
    fi
    sleep "$delay"
  done

  warn "Last /readyz error:"
  cat /tmp/agp-readyz.err >&2 || true
  show_agp_diagnostics
  rm -f /tmp/agp-readyz.out /tmp/agp-readyz.err
  return 1
}

install_systemd_units() {
  cd "$SOURCE_DIR"
  install -o root -g root -m 0644 deploy/systemd/agp.service /etc/systemd/system/agp.service
  systemctl daemon-reload
  systemctl enable agp
  systemctl restart agp
  wait_for_agp_ready 45 1
}

create_initial_admin() {
  if runuser -u agp -- /bin/sh -c 'set -a; . /etc/agp/agp.env; set +a; /usr/local/bin/agpctl create-admin -username "$0" -display-name "Administrator"' "$ADMIN_USER" <<<"$ADMIN_PASSWORD"; then
    log "Initial admin user created: $ADMIN_USER"
  else
    warn "Admin creation failed. It may already exist. Check: journalctl -u agp -n 100 --no-pager"
  fi
}

write_nginx_portal_http_config() {
  [[ "$SETUP_NGINX" == "yes" ]] || return
  cat >/etc/nginx/conf.d/agp-portal.conf <<EOF
upstream agp_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name ${PORTAL_HOST};

    location / {
        proxy_pass http://agp_backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
    }
}
EOF
  nginx -t
  systemctl reload nginx
}

request_certbot_certificate() {
  [[ "$SETUP_NGINX" == "yes" && "$SETUP_CERTBOT" == "yes" ]] || return
  certbot certonly --nginx \
    --non-interactive \
    --agree-tos \
    -m "$LE_EMAIL" \
    -d "$PORTAL_HOST"
}

write_nginx_portal_https_config() {
  [[ "$SETUP_NGINX" == "yes" ]] || return
  local cert="/etc/letsencrypt/live/${PORTAL_HOST}/fullchain.pem"
  local key="/etc/letsencrypt/live/${PORTAL_HOST}/privkey.pem"

  if [[ ! -f "$cert" || ! -f "$key" ]]; then
    warn "TLS certificate not found for $PORTAL_HOST. Leaving HTTP-only config in place."
    warn "Run certbot later, then rerun this installer or add HTTPS config manually."
    return
  fi

  cat >/etc/nginx/conf.d/agp-portal.conf <<EOF
upstream agp_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name ${PORTAL_HOST};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${PORTAL_HOST};

    ssl_certificate ${cert};
    ssl_certificate_key ${key};

    access_log /var/log/nginx/agp.portal.access.log;
    error_log /var/log/nginx/agp.portal.error.log warn;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header Content-Security-Policy "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'" always;

    location / {
        proxy_pass http://agp_backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
    }

    location = /metrics {
        allow 127.0.0.1;
        allow ::1;
        deny all;
        proxy_pass http://agp_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
  nginx -t
  systemctl reload nginx
}

configure_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    ufw allow OpenSSH || true
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true
    if ufw status | grep -q "Status: inactive"; then
      yes | ufw enable || true
    fi
    ufw status verbose || true
  fi
}

install_backups() {
  [[ "$SETUP_BACKUPS" == "yes" ]] || return
  cd "$SOURCE_DIR"
  install -o root -g root -m 0755 scripts/agp-backup.sh /usr/local/bin/agp-backup.sh
  install -o root -g root -m 0755 scripts/agp-restore.sh /usr/local/bin/agp-restore.sh
  install -o root -g root -m 0644 deploy/systemd/agp-backup.service /etc/systemd/system/agp-backup.service
  install -o root -g root -m 0644 deploy/systemd/agp-backup.timer /etc/systemd/system/agp-backup.timer
  install -d -o agp -g agp -m 0750 /var/backups/agp
  systemctl daemon-reload
  systemctl enable --now agp-backup.timer
}

final_checks() {
  systemctl status agp --no-pager || true
  wait_for_agp_ready 15 1
  PGPASSWORD="$DB_PASSWORD" psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -c 'select current_user, current_database();'
  if [[ "$SETUP_NGINX" == "yes" ]]; then
    nginx -t
  fi

  cat <<EOF

AGP installation finished.

Portal:
  https://${PORTAL_HOST}

Initial admin:
  username: ${ADMIN_USER}
EOF
  if [[ "$GENERATED_ADMIN_PASSWORD" == "yes" ]]; then
    cat <<EOF
  generated password: ${ADMIN_PASSWORD}

Save this generated admin password now. It will not be stored by the installer.
EOF
  fi
  cat <<EOF

PostgreSQL:
  database: ${DB_NAME}
  user:     ${DB_USER}
  password: stored in /etc/agp/agp.env

Useful checks:
  systemctl status agp --no-pager
  journalctl -u agp -n 100 --no-pager
  curl -fsS http://127.0.0.1:8080/readyz
EOF
}

main() {
  require_ubuntu
  require_command openssl
  collect_answers
  print_summary

  run_step "Install base packages" install_base_packages
  run_step "Install Go if missing or too old" install_go_if_needed
  [[ "$SETUP_NGINX" == "yes" ]] && run_step "Install official nginx.org Nginx" install_nginx_org
  [[ "$SETUP_CERTBOT" == "yes" ]] && run_step "Install certbot" install_certbot_if_enabled
  run_step "Configure PostgreSQL local security policy" configure_postgres
  run_step "Create PostgreSQL AGP role and database" create_postgres_database
  run_step "Prepare AGP source tree" prepare_source_tree
  run_step "Build and install AGP binaries" build_and_install_agp
  run_step "Create AGP OS user and directories" create_agp_user_and_dirs
  run_step "Write /etc/agp/agp.env" write_agp_env
  run_step "Install and start AGP systemd service" install_systemd_units
  run_step "Create initial AGP administrator" create_initial_admin
  [[ "$SETUP_NGINX" == "yes" ]] && run_step "Write temporary HTTP Nginx portal config" write_nginx_portal_http_config
  [[ "$SETUP_NGINX" == "yes" && "$SETUP_CERTBOT" == "yes" ]] && run_step "Request Let's Encrypt certificate" request_certbot_certificate
  [[ "$SETUP_NGINX" == "yes" ]] && run_step "Write final HTTPS Nginx portal config" write_nginx_portal_https_config
  run_step "Configure UFW firewall" configure_firewall
  [[ "$SETUP_BACKUPS" == "yes" ]] && run_step "Install backup scripts and timer" install_backups
  run_step "Run final checks" final_checks
}

main "$@"
