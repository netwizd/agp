# Nginx Recommendations

AGP generates Nginx configuration recommendations from stored resource metadata.
It does not apply them automatically.

The recommended operational flow is:

1. administrator creates or updates a resource in AGP;
2. administrator opens `GET /api/v1/admin/resources/{id}/nginx`;
3. AGP returns a server block snippet and warnings;
4. administrator reviews the snippet;
5. administrator runs `nginx -t`;
6. administrator reloads Nginx.

This keeps AGP as the access control plane while Nginx remains the data plane.
Automatic config application can be added later through a privileged local agent
with explicit RBAC, audit events and `nginx -t` gating.

Generated snippets redirect `403` responses to
`https://<portal-host>/access-denied`. AGP intentionally uses the same denial
surface for missing resources and unauthorized resources so users cannot infer
whether a guessed entry point exists.
