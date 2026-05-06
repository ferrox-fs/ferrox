# IAM

Ferrox v1 ships with a single-tenant identity (`--access-key` / `--secret-key`).

Multi-key + bucket-policy support is on the roadmap; the admin mTLS endpoint already exposes:

- `POST /admin/access-keys` — create new access-key pair
- `DELETE /admin/access-keys/{id}` — revoke
- `GET /admin/access-keys` — list

See **[mTLS Admin API](../operations/observability.md#admin-api)** for how to bootstrap admin client certs.
