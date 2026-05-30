# ADR 0001: Single-node MVP with SQLite and Nginx auth_request

## Status

Accepted.

## Context

AGP must become a centralized access boundary for internal services. The first
stage must be deployable on one VM while preserving a path to PostgreSQL and
multi-instance operation.

## Decision

Use Go for the backend, SQLite for initial persistence and Nginx `auth_request`
for reverse proxy authorization.

## Consequences

Benefits:

- low operational footprint;
- auditable authorization decision point;
- backend remains independent from specific internal resources;
- clean migration path to PostgreSQL through repository interfaces.

Tradeoffs:

- SQLite limits write concurrency and HA;
- in-memory rate limiting is node-local;
- admin CRUD and enterprise identity integrations remain later stages.
