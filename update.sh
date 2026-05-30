#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_ROOT="${INSTALL_ROOT:-/opt/agp-src}"
SERVICE_NAME="${SERVICE_NAME:-agp}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
ENV_FILE="${ENV_FILE:-/etc/agp/agp.env}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/agp/updates}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8080/healthz}"
READY_URL="${READY_URL:-http://127.0.0.1:8080/readyz}"
ORIGINAL_ARGS=("$@")

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR"
if [[ ! -f "$SOURCE_DIR/go.mod" ]]; then
  SOURCE_DIR="$INSTALL_ROOT"
fi

MODE="manual"
RUN_TESTS="yes"
GIT_PULL="yes"
ALLOW_DIRTY="no"
BACKUP_DIR=""
OLD_COMMIT="unknown"
NEW_COMMIT="unknown"
UPSTREAM_REF=""
REMOTE_COMMIT="unknown"
NO_UPDATE_REASON=""
TMP_DIR=""

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
  sudo ./update.sh
  sudo ./update.sh --auto
  sudo ./update.sh --manual

Options:
  --auto          run without per-step confirmations
  --manual        ask before each major step; default
  --skip-tests    build and install without go test/go vet
  --no-git-pull   update from the current working tree
  --allow-dirty   allow local uncommitted changes before update

Environment overrides:
  INSTALL_ROOT=/opt/agp-src
  SERVICE_NAME=agp
  BIN_DIR=/usr/local/bin
  ENV_FILE=/etc/agp/agp.env
  BACKUP_ROOT=/var/backups/agp/updates
  HEALTH_URL=http://127.0.0.1:8080/healthz
  READY_URL=http://127.0.0.1:8080/readyz
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
    --skip-tests)
      RUN_TESTS="no"
      shift
      ;;
    --no-git-pull)
      GIT_PULL="no"
      shift
      ;;
    --allow-dirty)
      ALLOW_DIRTY="yes"
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
  log "Re-running updater through sudo."
  exec sudo -E bash "$0" "${ORIGINAL_ARGS[@]}"
fi

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

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

preflight() {
  require_command git
  require_command go
  require_command install
  require_command systemctl
  require_command curl
  require_command mktemp

  [[ -d "$SOURCE_DIR" ]] || die "source directory not found: $SOURCE_DIR"
  [[ -f "$SOURCE_DIR/go.mod" ]] || die "go.mod not found in $SOURCE_DIR"
  [[ -f "$ENV_FILE" ]] || warn "AGP env file not found: $ENV_FILE"

  if ! systemctl list-unit-files "${SERVICE_NAME}.service" >/dev/null 2>&1; then
    warn "systemd unit ${SERVICE_NAME}.service is not known yet; update will install unit from deploy/systemd if available"
  fi

  cd "$SOURCE_DIR"
  OLD_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

  if [[ "$ALLOW_DIRTY" != "yes" ]] && [[ -n "$(git status --porcelain)" ]]; then
    git status --short >&2
    die "working tree is dirty; commit/stash local changes or rerun with --allow-dirty"
  fi
}

update_source() {
  cd "$SOURCE_DIR"
  if [[ "$GIT_PULL" != "yes" ]]; then
    warn "Skipping git pull by request."
    NEW_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    return
  fi

  local branch local_full remote_full
  branch="$(git rev-parse --abbrev-ref HEAD)"
  [[ "$branch" != "HEAD" ]] || die "source tree is detached; checkout a branch or use --no-git-pull"

  UPSTREAM_REF="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
  [[ -n "$UPSTREAM_REF" ]] || die "branch $branch has no upstream; set upstream or use --no-git-pull"

  git fetch --prune
  local_full="$(git rev-parse HEAD)"
  remote_full="$(git rev-parse "$UPSTREAM_REF")"
  REMOTE_COMMIT="$(git rev-parse --short "$UPSTREAM_REF" 2>/dev/null || echo unknown)"

  if [[ "$local_full" == "$remote_full" ]]; then
    NEW_COMMIT="$OLD_COMMIT"
    NO_UPDATE_REASON="local HEAD already matches upstream"
    log "No update available. Local HEAD already matches $UPSTREAM_REF ($OLD_COMMIT)."
    print_no_update_summary
    exit 0
  fi

  if git merge-base --is-ancestor "$UPSTREAM_REF" HEAD; then
    NEW_COMMIT="$OLD_COMMIT"
    NO_UPDATE_REASON="local branch is ahead of upstream; no remote update to apply"
    warn "$NO_UPDATE_REASON"
    print_no_update_summary
    exit 0
  fi

  if ! git merge-base --is-ancestor HEAD "$UPSTREAM_REF"; then
    die "local branch and $UPSTREAM_REF have diverged; resolve manually before updating"
  fi

  git pull --ff-only
  NEW_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
}

print_no_update_summary() {
  cat <<EOF

AGP is already up to date.
  source dir:       $SOURCE_DIR
  service:          $SERVICE_NAME
  current commit:   $OLD_COMMIT
  upstream:         ${UPSTREAM_REF:-not checked}
  upstream commit:  $REMOTE_COMMIT
  reason:           ${NO_UPDATE_REASON:-no remote update available}

No build, install, restart or migration was performed.
EOF
}

build_release() {
  cd "$SOURCE_DIR"
  export PATH="/usr/local/go/bin:$PATH"
  TMP_DIR="$(mktemp -d)"

  go mod download
  if [[ "$RUN_TESTS" == "yes" ]]; then
    go test ./...
    go vet ./...
  else
    warn "Skipping go test/go vet by request."
  fi

  local version commit built_at ldflags
  version="${AGP_VERSION:-$(cat VERSION 2>/dev/null || echo v1.0.0-dev)}"
  commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  ldflags="-X github.com/netwizd/agp/internal/version.Version=${version} -X github.com/netwizd/agp/internal/version.Commit=${commit} -X github.com/netwizd/agp/internal/version.BuiltAt=${built_at}"

  go build -trimpath -ldflags "$ldflags" -o "$TMP_DIR/agp" ./cmd/agp
  go build -trimpath -ldflags "$ldflags" -o "$TMP_DIR/agpctl" ./cmd/agpctl

  "$TMP_DIR/agp" --version
  "$TMP_DIR/agpctl" version
}

backup_current_install() {
  BACKUP_DIR="$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-${OLD_COMMIT}"
  install -d -o root -g root -m 0700 "$BACKUP_DIR"

  [[ -x "$BIN_DIR/agp" ]] && cp -a "$BIN_DIR/agp" "$BACKUP_DIR/agp"
  [[ -x "$BIN_DIR/agpctl" ]] && cp -a "$BIN_DIR/agpctl" "$BACKUP_DIR/agpctl"
  [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]] && cp -a "/etc/systemd/system/${SERVICE_NAME}.service" "$BACKUP_DIR/${SERVICE_NAME}.service"
  [[ -f "$ENV_FILE" ]] && cp -a "$ENV_FILE" "$BACKUP_DIR/agp.env"

  log "Backup directory: $BACKUP_DIR"
}

install_release() {
  install -o root -g root -m 0755 "$TMP_DIR/agp" "$BIN_DIR/agp"
  install -o root -g root -m 0755 "$TMP_DIR/agpctl" "$BIN_DIR/agpctl"

  if [[ -f "$SOURCE_DIR/deploy/systemd/agp.service" ]]; then
    install -o root -g root -m 0644 "$SOURCE_DIR/deploy/systemd/agp.service" "/etc/systemd/system/${SERVICE_NAME}.service"
  fi
  if [[ -f "$SOURCE_DIR/scripts/agp-backup.sh" ]]; then
    install -o root -g root -m 0755 "$SOURCE_DIR/scripts/agp-backup.sh" /usr/local/bin/agp-backup.sh
  fi
  if [[ -f "$SOURCE_DIR/scripts/agp-restore.sh" ]]; then
    install -o root -g root -m 0755 "$SOURCE_DIR/scripts/agp-restore.sh" /usr/local/bin/agp-restore.sh
  fi
  if [[ -f "$SOURCE_DIR/deploy/systemd/agp-backup.service" ]]; then
    install -o root -g root -m 0644 "$SOURCE_DIR/deploy/systemd/agp-backup.service" /etc/systemd/system/agp-backup.service
  fi
  if [[ -f "$SOURCE_DIR/deploy/systemd/agp-backup.timer" ]]; then
    install -o root -g root -m 0644 "$SOURCE_DIR/deploy/systemd/agp-backup.timer" /etc/systemd/system/agp-backup.timer
  fi

  systemctl daemon-reload
}

show_agp_diagnostics() {
  warn "AGP did not become ready. Diagnostics:"
  systemctl status "$SERVICE_NAME" --no-pager || true
  journalctl -u "$SERVICE_NAME" -n 120 --no-pager || true
}

wait_for_ready() {
  local attempts="${1:-60}"
  local delay="${2:-1}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS "$READY_URL" >/tmp/agp-update-readyz.out 2>/tmp/agp-update-readyz.err; then
      cat /tmp/agp-update-readyz.out
      rm -f /tmp/agp-update-readyz.out /tmp/agp-update-readyz.err
      return 0
    fi
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
      show_agp_diagnostics
      rm -f /tmp/agp-update-readyz.out /tmp/agp-update-readyz.err
      return 1
    fi
    sleep "$delay"
  done

  warn "Last readiness error:"
  cat /tmp/agp-update-readyz.err >&2 || true
  show_agp_diagnostics
  rm -f /tmp/agp-update-readyz.out /tmp/agp-update-readyz.err
  return 1
}

rollback_install() {
  [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]] || die "rollback requested but backup directory is missing"
  warn "Rolling back binaries from $BACKUP_DIR"

  [[ -f "$BACKUP_DIR/agp" ]] && install -o root -g root -m 0755 "$BACKUP_DIR/agp" "$BIN_DIR/agp"
  [[ -f "$BACKUP_DIR/agpctl" ]] && install -o root -g root -m 0755 "$BACKUP_DIR/agpctl" "$BIN_DIR/agpctl"
  if [[ -f "$BACKUP_DIR/${SERVICE_NAME}.service" ]]; then
    install -o root -g root -m 0644 "$BACKUP_DIR/${SERVICE_NAME}.service" "/etc/systemd/system/${SERVICE_NAME}.service"
  fi
  systemctl daemon-reload
  systemctl restart "$SERVICE_NAME" || true
  wait_for_ready 30 1 || true
}

restart_service() {
  systemctl restart "$SERVICE_NAME"
  if ! wait_for_ready 60 1; then
    rollback_install
    die "updated AGP failed readiness check; rollback attempted"
  fi

  curl -fsS "$HEALTH_URL" >/dev/null
  curl -fsS "$READY_URL" >/dev/null
}

print_summary() {
  cat <<EOF

AGP update complete.
  source dir:       $SOURCE_DIR
  service:          $SERVICE_NAME
  old commit:       $OLD_COMMIT
  new commit:       $NEW_COMMIT
  backup dir:       $BACKUP_DIR
  env file:         $ENV_FILE
  health URL:       $HEALTH_URL
  readiness URL:    $READY_URL

Installed versions:
EOF
  "$BIN_DIR/agp" --version || true
  "$BIN_DIR/agpctl" version || true

  cat <<EOF

Useful checks:
  systemctl status $SERVICE_NAME --no-pager
  journalctl -u $SERVICE_NAME -n 100 --no-pager
EOF
}

main() {
  run_step "Preflight checks" preflight
  run_step "Update source tree" update_source
  run_step "Build release" build_release
  run_step "Backup current install" backup_current_install
  run_step "Install release files" install_release
  run_step "Restart AGP and verify readiness" restart_service
  print_summary
}

main
