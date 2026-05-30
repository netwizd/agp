# Admin API

Admin endpoints require:

1. a valid AGP session;
2. the permission required by the endpoint;
3. `X-CSRF-Token` for state-changing methods.

`is_admin=true` remains a compatibility superuser flag and grants all known
permissions. See [rbac.md](rbac.md).

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/admin/dashboard` | dashboard counters and recent audit events |
| `GET` | `/api/v1/admin/users` | list users |
| `POST` | `/api/v1/admin/users` | create user |
| `PATCH` | `/api/v1/admin/users/{id}` | update user, password, block flag or groups |
| `DELETE` | `/api/v1/admin/users/{id}` | delete user |
| `GET` | `/api/v1/admin/groups` | list groups |
| `POST` | `/api/v1/admin/groups` | create group |
| `PATCH` | `/api/v1/admin/groups/{id}` | update group |
| `DELETE` | `/api/v1/admin/groups/{id}` | delete group |
| `GET` | `/api/v1/admin/resources` | list resources |
| `POST` | `/api/v1/admin/resources` | create resource |
| `GET` | `/api/v1/admin/resources/{id}` | get resource details |
| `PATCH` | `/api/v1/admin/resources/{id}` | update resource, groups or IP allowlist |
| `DELETE` | `/api/v1/admin/resources/{id}` | delete resource |
| `GET` | `/api/v1/admin/resources/{id}/nginx` | generate Nginx recommendation |
| `POST` | `/api/v1/admin/resources/{id}/diagnostics` | run upstream DNS/TCP/HTTP diagnostics |
| `GET` | `/api/v1/admin/downloads` | list public downloads, including disabled entries |
| `POST` | `/api/v1/admin/downloads` | upload a public download via multipart form data |
| `PATCH` | `/api/v1/admin/downloads/{id}` | update public download title, description or enabled flag |
| `DELETE` | `/api/v1/admin/downloads/{id}` | delete public download metadata and file |
| `GET` | `/api/v1/admin/portal-settings` | read portal branding and helper text |
| `PUT` | `/api/v1/admin/portal-settings` | update portal branding and helper text |
| `GET` | `/api/v1/admin/sessions` | list active sessions |
| `DELETE` | `/api/v1/admin/sessions/{id}` | revoke session |
| `GET` | `/api/v1/admin/audit?limit=100` | list audit events |
| `GET` | `/api/v1/admin/audit/export?format=csv` | export audit events; requires `audit.export` |

## Public Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/public/settings` | read portal branding and helper text without auth |
| `GET` | `/api/v1/public/downloads` | list enabled public downloads without auth |
| `GET` | `/downloads/{id}` | download an enabled public file without auth |

## Resource Create Example

```json
{
  "name": "Example App",
  "description": "Internal example service",
  "category": "Operations",
  "internal_url": "http://app.internal.local/anything-needed",
  "public_host": "enter.company.ru",
  "public_path": "/anything-needed",
  "enabled": true,
  "group_ids": ["grp_admins"],
  "allow_cidrs": ["10.50.0.0/16"]
}
```

`public_host` is the public portal host. `public_path` is the protected entry
point on that host. With the example above AGP expects Nginx to protect
`https://enter.company.ru/anything-needed` and proxy it to
`http://app.internal.local/anything-needed`.

The API validates public host, public path, internal URL and CIDR syntax before
storing a resource.

Resource diagnostics are subject to `AGP_DIAGNOSTICS_ALLOW_CIDRS`,
`AGP_DIAGNOSTICS_DENY_CIDRS` and per-user/resource rate limiting. By default,
loopback, link-local and metadata-style target ranges are blocked.
