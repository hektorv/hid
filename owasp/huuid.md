# Hierarchical Resource Identifiers: Secure Patterns for Access-Controlled APIs

## 1. Introduction
- API resource hierarchies
- Risk of tampering and escalation

## 2. Common Threats
- ID tampering (`/projects/1/`)
- Privilege escalation
- Insecure UUID usage

## 3. Secure ID Generation
- Overview of HUUID and HID64
- HMAC binding to parent
- Stateless local validation

## 4. Implementation Guidelines
- Per-tenant secret keys via HKDF
- Recommendations for prefix/suffix sizes
- Example with `projects/{pid}/iterations/{iid}`

## 5. Validation and Key Rotation
- Safe use of rotation bits (HUUID only)
- Stateless decoding examples

## 6. Use Cases
- Multi-tenant APIs
- Logs, artifacts, and event tracing
- Edge computing with offline validation

## 7. Comparison Table
- vs UUIDv4, Snowflake, KSUID

## 8. References
- RFC 9562, RFC 4122
- OWASP API Security Top 10



# Hierarchical Resource Identifiers: Secure Patterns for Access-Controlled APIs

## 1. Introduction

Modern APIs increasingly expose deeply nested resource structures (e.g. `/projects/{pid}/iterations/{iid}/activities/{aid}`), making them vulnerable to ID tampering, privilege escalation, and insecure direct object references (IDOR). Standard UUIDs and database-generated IDs offer no structural protection or hierarchy enforcement.

This document presents **HUUID** (Hierarchical UUID) and **HID64** (Hierarchical Identifier 64-bit), two formats designed to mitigate these issues by encoding secure, HMAC-based parent-child relationships directly into resource identifiers.

## 2. Threat Model

| Threat | Description |
|--------|-------------|
| ID Tampering | Guessing valid child IDs under a known parent |
| Horizontal Escalation | Changing a resource ID to access peer data |
| Spoofing | Generating fake IDs not authorized by API hierarchy |
| Inference | Deducting structure from UUID patterns |

## 3. Secure Identifier Designs

### HUUID (UUIDv8-Compatible)

- Uses HMAC(parent_id, key) to derive a prefix
- Encoded into the `node` field of UUIDv8 (RFC 9562)
- Enables local validation without DB access
- Fully compatible with existing UUID libraries

### HID64 (64-bit Compact Form)

- 32-bit HMAC-derived prefix + 32-bit random suffix
- Fits into native `uint64` for DBs, protocols
- Optimized for systems with ≤100k siblings per parent

## 4. Generation Patterns

- HMAC-SHA256 with tenant-scoped keys (`HKDF`)
- Stateless generation: only parent ID and key needed
- No need for coordination or central registry

## 5. Validation

- Perform local validation by recomputing HMAC
- Prevents unauthorized creation or guessing of IDs
- Example shown in Python for both formats

## 6. Use Cases

- Secure APIs (RESTful hierarchies)
- Edge devices with offline validation
- Multi-tenant databases
- Distributed resource modeling

## 7. Comparison

| Property | HUUID | HID64 | UUIDv4 | Snowflake |
|----------|-------|--------|--------|-----------|
| Stateless generation | ✅ | ✅ | ✅ | ❌ |
| Hierarchy enforcement | ✅ | ✅ | ❌ | ❌ |
| UUID compatibility | ✅ | ❌ | ✅ | ❌ |
| Fixed-length (binary) | ✅ | ✅ | ✅ | ✅ |
| Local validation | ✅ | ✅ | ❌ | ❌ |

## 8. References

- [RFC 4122 – UUID](https://datatracker.ietf.org/doc/html/rfc4122)
- [RFC 9562 – UUIDv8](https://datatracker.ietf.org/doc/html/rfc9562)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
