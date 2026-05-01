# HID64 and HUUID

Hierarchical identifier formats with cryptographic local validation.
HUUID is a 128-bit UUIDv8-compatible identifier (RFC 9562); HID64 is a
compact 64-bit variant. Both bind a child identifier to its parent (and
to a previously authenticated root) via HMAC-SHA256, so a service can
validate hierarchical relationships locally — without database lookups
or central coordination — and reject forged identifiers from holders
who do not possess the per-tenant secret.

## Origin

These formats emerged from a concrete problem: a three-level REST
hierarchy (`/projects/{p}/iterations/{i}/tasks/{t}`) where authorization
checks at the edge required validating the chain segment by segment,
each segment costing a database query. The HMAC-bound prefix replaces
those queries with a single local computation per segment. HUUID exists
because the leaf identifier needed to remain UUID-compatible for
existing infrastructure; HID64 exists because the same construction
fits in 8 bytes when UUID compatibility is not a constraint.

## Status

- Specifications: **v1.0 (stable)** — May 2025; first public release April 2026
- Reference implementation: Python (HID64 and HUUID) — complete and tested
- Other language ports: Go, Rust, Java — present in this repository but
  implement an earlier pre-v1.0 construction (SHA-256 only, no HMAC).
  They are preserved as historical artifacts; v1.0-compliant ports are
  welcome as external contributions.

This repository contains the specifications, the Python reference
implementation, an OWASP-style threat note, and an IETF-style
Internet-Draft.

## Repository layout

```
hid64/                 HID64 specification + Python reference + ports
  specs/HID64-spec-v1.0.md
  src/python/hid64.py
  tests/python/
  src/{go,rust,java}/   (pre-v1.0; preserved as historical artifacts)
huuid/                 HUUID specification + Python reference
  spec/HUUID-spec-v1.0.md
  src/python/huuid.py
  tests/python/
IETF/                  Internet-Draft (informational, not yet submitted)
owasp/                 Threat-model note for hierarchical resource IDs
```

## Install (Python, editable)

Each subproject is installable independently and only requires
Python ≥ 3.8.

```sh
# HID64 reference implementation (depends on `cryptography` for HKDF)
cd hid64 && pip install -e .

# HUUID reference implementation (no external deps)
cd huuid && pip install -e .
```

## Quick start — HID64

```python
from hid64 import derive_key, generate_hid64, validate_hid64

master_key = b"replace-with-securely-stored-master-key"
tenant_key = derive_key(master_key, "tenant:acme")

root_id   = "tenant:acme"   # must be authenticated externally (JWT/OAuth/etc.)
parent_id = "app:42"

hid = generate_hid64(root_id, parent_id, tenant_key)
assert validate_hid64(root_id, parent_id, hid, tenant_key)
```

## Quick start — HUUID

```python
from huuid import generate_huuid, validate_huuid

secret    = b"replace-with-tenant-scoped-secret"
parent_id = "account:42"

huuid = generate_huuid(parent_id, secret)   # returns a standard uuid.UUID
assert validate_huuid(parent_id, huuid, secret)
print(str(huuid))   # e.g. "861f6b20-e1cc-8942-b135-e412be9faa3e"
```

For an end-to-end example that combines HUUID with a JWT-based session
(stateless tenant validation at the edge, no database lookup), see
[`huuid/examples/jwt_validation.py`](huuid/examples/jwt_validation.py).

## Security model

Both formats are designed to make hierarchy **locally verifiable** and
**hard to forge**, given a per-tenant secret. They are not a substitute
for authentication or authorization.

What the formats provide:

- **HMAC binding to parent.** The prefix portion of the identifier is
  `HMAC-SHA256(secret, context)` truncated. For HID64 the context is
  `"root_id:parent_id"`; for HUUID it is `parent_id`. A holder without
  the secret cannot forge a child that validates under a given parent.
- **Stateless validation.** Verification recomputes the HMAC; no
  database or network call is needed.
- **Per-tenant key isolation.** Use HKDF to derive a tenant- or
  context-scoped key from a master key, so a leak in one tenant does
  not compromise sibling tenants.
- **Cross-tree separation (HID64).** Including `root_id` in the HMAC
  context isolates ID trees that share a parent label.

What they do **not** provide:

- **Authentication of the root.** The `root_id` (e.g. tenant or
  account) MUST be authenticated and authorized externally before
  generation or validation — typically via JWT, OAuth/OIDC, mTLS, API
  keys, or RBAC. The formats assume this has already happened.
- **Revocation.** Once issued, an identifier cannot be revoked by the
  format itself; revocation requires external bookkeeping.
- **Confidentiality of the parent.** The parent label is not encrypted;
  the HMAC only prevents forgery and inference, not disclosure of a
  parent ID that is already known.
- **Replacement of database integrity.** Foreign-key and
  ownership constraints in the system of record remain authoritative.

A more detailed threat-model sketch is in [`owasp/huuid.md`](owasp/huuid.md).

## When to use these formats

Use HID64 or HUUID when:

- Validation must happen at edges where the database is not reachable
  (API gateways, edge nodes, log/event consumers).
- Multi-tenant isolation should be enforced cryptographically in the
  identifier itself, not only at query time.
- You need fixed-length, statelessly-derivable IDs that survive
  round-trips through URLs, message payloads, and external systems.

Do **not** use them as a replacement for:

- Database-level referential integrity. Foreign keys still belong in
  the database.
- Authentication or authorization. The formats only verify
  parent-child structure given a key; they say nothing about whether
  the caller is allowed to perform the action.

For more detail on scope and tradeoffs, see [`scope.md`](scope.md) and
[`tradeofs`](tradeofs).

## Choosing between HID64 and HUUID

| Property                         | HID64               | HUUID                    |
|----------------------------------|---------------------|--------------------------|
| Width                            | 64 bits             | 128 bits (UUIDv8)        |
| UUID-library compatibility       | No                  | Yes (RFC 9562)           |
| HMAC prefix size (default)       | 32 bits             | 24 bits (3 bytes)        |
| Random suffix size (default)     | 32 bits             | 24 bits (3 bytes)        |
| Best fit                         | `BIGINT` columns, compact wire formats | UUID columns, drop-in for existing UUID infra |

## Specifications

- [HID64 v1.0](hid64/specs/HID64-spec-v1.0.md)
- [HUUID v1.0](huuid/spec/HUUID-spec-v1.0.md)
- [IETF Internet-Draft (HUUID + HID64)](IETF/huuid-internet-draft.md) — informational, not yet submitted

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests are
welcome — particularly v1.0-compliant ports for Go, Rust, and Java, and
additional test vectors for cross-implementation conformance.

## License

[MIT](LICENSE) © 2025 Héctor Villa.
