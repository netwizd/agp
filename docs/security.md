# AGP Security Model

## Trust Boundaries

AGP backend must not be directly exposed to untrusted networks. It trusts
`X-Real-IP`, `X-Forwarded-*` and `Cookie` headers only when requests come from
the local Nginx reverse proxy.

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

## Auditability

Audit events are persisted for:

- successful and failed logins;
- logout;
- `auth_request` authorization decisions;
- denied IP/resource/group decisions.

For production, SQLite audit retention should be paired with backup and export.
For enterprise scale, audit storage should move to PostgreSQL and/or SIEM.

## Known MVP Limits

- Rate limiting is in-memory and suitable for a single backend instance only.
- Admin CRUD API is not implemented in the first scaffold.
- LDAP, AD, TOTP and SSO are planned for enterprise stages.
