# Nginx Recommendations

AGP generates Nginx configuration recommendations from stored resource metadata.
It does not apply them automatically.

The recommended operational flow is:

1. administrator creates or updates a resource in AGP;
2. administrator opens `GET /api/v1/admin/resources/{id}/nginx`;
3. AGP returns a protected `location` snippet for path-based resources or a
   legacy server block snippet for host-based resources;
4. administrator reviews the snippet;
5. administrator runs `nginx -t`;
6. administrator reloads Nginx.

The default production model is one public portal host with many protected
paths. For example, resource metadata
`public_host=enter.company.ru`, `public_path=/anything-needed`,
`internal_url=http://app.internal.local/anything-needed` produces a protected Nginx
location on the portal server. The location uses `auth_request /_agp_auth`
before `proxy_pass`, so access is still controlled by AGP sessions, groups and
optional CIDR allowlists.

Path-based snippets also include `proxy_redirect` and cookie rewrite directives.
This keeps upstream redirects such as
`Location: http://app.internal.local/anything-needed/ru_RU` inside the public
portal URL, for example `https://enter.company.ru/anything-needed/ru_RU`.

This keeps AGP as the access control plane while Nginx remains the data plane.
Automatic config application can be added later through a privileged local agent
with explicit RBAC, audit events and `nginx -t` gating.

Generated snippets redirect `403` responses to
`https://<portal-host>/access-denied`. AGP intentionally uses the same denial
surface for missing resources and unauthorized resources so users cannot infer
whether a guessed entry point exists.

The portal server snippet includes CSP and HSTS headers. Legacy resource server
snippets include HSTS and baseline hardening headers, but do not inject a CSP
because proxied applications may have their own content policy requirements.
