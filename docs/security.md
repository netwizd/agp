# AGP Security Model

## Trust Boundaries

AGP backend must not be directly exposed to untrusted networks. It trusts
`X-Real-IP`, `X-Forwarded-*` and `Cookie` headers only when requests come from
configured trusted proxy CIDRs. `/auth/request` also rejects direct callers when
proxy-header trust is enabled and the remote address is not trusted.

## Authentication

- Passwords use Argon2id.
- Session cookies are `HttpOnly`, `Secure`, `SameSite=Lax`.
- Session tokens are stored as SHA-256 hashes in the database.
- CSRF uses a double-submit style token for state-changing API calls.

## Authorization

Access to resources requires all checks to pass:

1. valid non-expired session;
2. non-blocked user;
3. enabled resource mapped by public host;
4. client IP inside resource allowlist when allowlist exists;
5. user group intersects with resource groups.

The system must fail closed on storage errors, invalid allowlist CIDRs and
unknown resources.

Missing resources and unauthorized resources are intentionally presented through
the same access-denied UX. Operators should avoid custom Nginx error pages that
reveal whether a guessed hostname or path exists.

## Auditability

Audit events are persisted for:

- successful and failed logins;
- logout;
- `auth_request` authorization decisions;
- denied IP/resource/group decisions;
- audit exports and administrative diagnostics runs.

CSV audit exports escape spreadsheet formula-leading cells to avoid formula
execution when operators open exported files in office tools.

## Diagnostics

Resource diagnostics are privileged administrative probes. They are rate-limited
per user/resource and evaluated against `AGP_DIAGNOSTICS_ALLOW_CIDRS` /
`AGP_DIAGNOSTICS_DENY_CIDRS` before TCP or HTTP checks. By default, loopback,
link-local and metadata-style target ranges are denied.

For production, SQLite audit retention should be paired with backup and export.
For enterprise scale, audit storage should move to PostgreSQL and/or SIEM.

## Known MVP Limits

- Rate limiting is in-memory and suitable for a single backend instance only.
- LDAP, AD, TOTP and SSO are planned for enterprise stages.
