# Admin API

Admin endpoints require:

1. a valid AGP session;
2. `is_admin=true` on the current user;
3. `X-CSRF-Token` for state-changing methods.

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
| `GET` | `/api/v1/admin/sessions` | list active sessions |
| `DELETE` | `/api/v1/admin/sessions/{id}` | revoke session |
| `GET` | `/api/v1/admin/audit?limit=100` | list audit events |

## Resource Create Example

```json
{
  "name": "1C Enterprise",
  "description": "Internal 1C service",
  "internal_url": "http://e1c.osrp.local",
  "public_host": "e1c.company.ru",
  "enabled": true,
  "group_ids": ["grp_admins"],
  "allow_cidrs": ["10.50.0.0/16"]
}
```

The API validates public host, internal URL and CIDR syntax before storing a
resource.
