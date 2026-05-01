title: "Hierarchical UUIDs and Compact 64-bit Identifiers for Secure Resource Modeling"
abbrev: HUUID/HID64
docname: draft-hhvilla-huuid-hid64-00
category: info
author:
  - name: Héctor Villa
    org: Independent
date: 2025-05-05
status: draft
---

# Status of This Document

This is a working draft written in Internet-Draft conventions. It has
**not** been submitted to the IETF datatracker and there is no current
plan to do so. It is preserved within this repository as a combined
informational overview of the HUUID and HID64 formats. The canonical,
normative specifications are the per-format documents at
`hid64/specs/HID64-spec-v1.0.md` and `huuid/spec/HUUID-spec-v1.0.md`;
in case of any discrepancy between this draft and those specs, the
per-format specs prevail.

# Abstract

This document introduces two hierarchical identifier formats: HUUID (UUIDv8-compatible) and HID64 (compact 64-bit form), designed for secure, stateless, and decentralized identification in distributed systems and multi-tenant environments. Both formats leverage HMAC-SHA256 to securely derive child resource identifiers from a parent ID, enabling local validation without centralized coordination. The HUUID format maintains compatibility with the UUID standard (RFC 4122), while HID64 provides a compact 64-bit alternative. This approach mitigates ID forgery risk, reduces collisions, and supports scalable resource modeling in environments such as RESTful APIs and microservices.

# 1. Introduction

In modern distributed systems, APIs, and multi-tenant applications, efficient and secure hierarchical resource identification is critical. Traditional approaches rely on centralized databases or coordination to verify resource relationships, which can cause latency and scalability issues.

This document proposes two identifier formats—HUUID and HID64—that enable stateless derivation of child IDs bound to a parent ID using HMAC-SHA256. This allows local validation without external lookups, improving performance and security in distributed environments.

- **HUUID (Hierarchical UUID)** is based on UUIDv8 (RFC 9562), embedding an HMAC-derived prefix in the UUID’s node field while preserving full UUID compatibility.

- **HID64 (Hierarchical 64-bit Identifier)** provides a compact 64-bit format combining an HMAC-derived 32-bit prefix with a 32-bit random suffix for uniqueness.

These formats suit scenarios requiring high scalability, fast local validation, and secure hierarchical modeling such as RESTful APIs, microservices, and multi-tenant cloud systems.

# 2. Terminology

- **HUUID (Hierarchical UUID):** A 128-bit hierarchical identifier based on UUIDv8 embedding an HMAC-derived prefix in the `node` field to cryptographically bind child IDs to a parent.

- **HID64 (Hierarchical 64-bit Identifier):** A compact 64-bit ID with a 32-bit HMAC prefix and 32-bit random suffix ensuring uniqueness and cryptographic linkage to a previously authenticated root and its immediate parent.

- **Parent ID:** Identifier representing an ancestor resource; used to derive child IDs.

- **Child ID:** Identifier derived from a Parent ID, cryptographically linked via HMAC.

- **HMAC:** Hash-based Message Authentication Code used to derive prefixes, keyed by a shared secret.

- **UUID:** Standard 128-bit unique identifier (RFC 4122); UUIDv8 allows custom fields.

- **Entropy:** Random data added to suffixes to reduce collisions.

- **Stateless Validation:** Verification of IDs without external state by recomputing HMAC prefixes.

# 3. Identifier Formats

## 3.1 HUUID (UUIDv8-Compatible)

HUUID is a 128-bit UUIDv8-compatible identifier embedding a truncated HMAC prefix derived from the parent ID into the 48-bit `node` field. Remaining fields contain random entropy to prevent collisions.

| Field                  | Bits | Description                                      |
|------------------------|------|-------------------------------------------------|
| `time_low`             | 32   | Random entropy                                   |
| `time_mid`             | 16   | Random entropy                                   |
| `time_hi_and_version`  | 16   | Version 8 (bits 12–15 = `1000`), plus random bits |
| `clock_seq_hi_variant` | 8    | RFC 4122 variant (bits 6–7 = `10`), plus random bits |
| `clock_seq_low`        | 8    | Random entropy                                  |
| `node`                 | 48   | HMAC prefix (N bytes, typically 2–4) + random suffix |

### Byte Order

- `time_low`, `time_mid`, `time_hi_and_version`: little-endian
- `clock_seq` and `node`: big-endian
- HMAC prefix inserted into `node` in big-endian order

HUUIDs remain fully compatible with existing UUID parsers.

## 3.2 HID64 (Compact 64-bit Form)

HID64 is a 64-bit unsigned integer:

| Field         | Bits | Description                                              |
|---------------|------|----------------------------------------------------------|
| HMAC prefix   | 32   | First 4 bytes of `HMAC-SHA256(secret, "root_id:parent_id")` |
| Random suffix | 32   | Random 32-bit value for uniqueness                       |

The HMAC binds the identifier both to an externally-authenticated `root_id` and to the immediate `parent_id`, isolating ID trees that share parent labels across unrelated roots. This format is not UUID-compatible but is compact and suitable for bandwidth/storage-constrained environments.

### Pseudocode

```python
prefix = HMAC_SHA256(secret, f"{root_id}:{parent_id}")[:4]
suffix = random_bytes(4)
hid64 = (prefix << 32) | suffix
```

# 4. Generation and Validation

Both formats use HMAC-SHA256 keyed with a shared secret to bind child IDs to their hierarchy.

## 4.1 HMAC Computation

The HMAC context differs by format:

```python
# HUUID: single-parent context
hmac = HMAC_SHA256(secret_key, parent_id)

# HID64: two-level context (externally-authenticated root + parent)
hmac = HMAC_SHA256(secret_key, f"{root_id}:{parent_id}")
```

The prefix length trades off hierarchy strength versus entropy.

## 4.2 HUUID Generation

1. Compute HMAC and take N bytes as prefix (2–4 typical)
2. Generate (6 - N) random bytes as suffix
3. Insert prefix + suffix into 48-bit `node` field
4. Set UUID version to 8, variant to RFC 4122
5. Fill other UUID fields with random data

## 4.3 HID64 Generation

1. Compute `HMAC_SHA256(secret, f"{root_id}:{parent_id}")` and take the first 4 bytes as the prefix
2. Generate a 4-byte random suffix
3. Concatenate prefix and suffix into a 64-bit integer

The `root_id` MUST be authenticated externally (e.g. via JWT, OAuth, mTLS) before generation.

## 4.4 Validation

Recompute HMAC prefix from claimed parent and secret; verify prefix matches embedded prefix in child ID.

# 5. Security Considerations

* **Forgery Resistance:** HMAC with secret key prevents forgery.
* **Key Management:** Keys should be 128+ bits, tenant-specific via HKDF, rotated regularly.
* **Collision Probability:** Suffix entropy ensures low collision risk at scale.
* **Replay Risks:** Keys must remain confidential; clients get only their IDs.
* **Stateless Validation:** Enables efficient edge validation without central coordination.

# 6. Implementation Notes

* Reference Python code provided for generation and validation.
* Supported in common languages with UUIDv8 and HMAC-SHA256 support.
* Storage: HUUID as UUID or 16-byte binary; HID64 as BIGINT or base64url.
* Validation requires a single HMAC operation; stateless and fast.

# 7. IANA Considerations

No registries or assignments requested.

# 8. References

* [RFC 4122](https://datatracker.ietf.org/doc/html/rfc4122)
* [RFC 9562](https://datatracker.ietf.org/doc/html/rfc9562)
* [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
