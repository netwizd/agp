# RBAC

AGP uses permission-based RBAC for administrative APIs.

## Compatibility Mode

`users.is_admin=true` is still supported as a superuser compatibility flag.
Such users receive all known permissions at session lookup time.

For normal administrators, prefer group-based permissions:

```text
user -> user_groups -> groups -> group_permissions -> permissions
```

## Permissions

| Permission | Purpose |
| --- | --- |
| `dashboard.read` | Read administrative dashboard |
| `users.read` | List users |
| `users.manage` | Create, update and delete users |
| `groups.read` | List groups |
| `groups.manage` | Create, update and delete groups |
| `resources.read` | List resources |
| `resources.manage` | Create, update and delete resources |
| `resources.diagnostics` | Run resource diagnostics |
| `nginx.recommendations.read` | Generate Nginx recommendations |
| `downloads.read` | List public downloads in admin |
| `downloads.manage` | Upload, publish, hide and delete public downloads |
| `portal.settings.read` | Read portal branding/settings in admin |
| `portal.settings.manage` | Update portal branding/settings |
| `sessions.read` | List active sessions |
| `sessions.revoke` | Revoke sessions |
| `audit.read` | Read audit events |
| `audit.export` | Export audit events |

## Group Management

Groups accept `permission_ids` through the Admin API:

```json
{
  "name": "Resource Operators",
  "description": "Manage published resources",
  "permission_ids": [
    "resources.read",
    "resources.manage",
    "nginx.recommendations.read",
    "resources.diagnostics"
  ]
}
```

The embedded admin UI also exposes a comma-separated permission field when
creating groups.

## Security Notes

- Permissions are evaluated on every session lookup.
- Blocked users are rejected even when they still have active sessions.
- Missing permission returns `403`.
- Audit export is separated from audit read because exported files contain IP,
  User-Agent and administrative metadata.
- `is_admin=true` should be treated as a break-glass/superuser mode and used
  sparingly in production.
