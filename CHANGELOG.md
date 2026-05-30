# Changelog

## v1.0.0-dev

- Hardened global administrator management with separate super-admin permission checks.
- Switched trusted proxy headers to secure-by-default configuration with trusted CIDR validation.
- Made readiness and metrics use cheap storage liveness checks.
- Added structured audit metadata for critical administrative actions.
- Added public download SHA-256 checksums, extension policy and optional scanner hook.
- Added inline admin editing for users, groups and public download metadata.
- Added Nginx full bundle generation endpoint and admin UI action.
- Added release build metadata, version endpoint and CLI version output.
- Added PostgreSQL-backed release gate, backup/restore scripts and systemd backup timer.
