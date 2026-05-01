# Changelog

All notable changes to the HID64 and HUUID specifications and reference
implementations are documented here. The project follows [Semantic
Versioning](https://semver.org/) for the specification version.

## [1.0.0] — 2026-04-30

First public release. Specifications are stable as of May 2025; the
reference implementation, threat model, and combined Internet-Draft
markdown are released for public review and use.

### Specifications
- HID64 v1.0: 32-bit HMAC-SHA256 prefix bound to `root_id:parent_id`
  with HKDF-derived per-tenant keys, plus 32-bit random suffix.
- HUUID v1.0: UUIDv8-compatible (RFC 9562) with HMAC-SHA256 prefix
  embedded in the `node` field.
- Both specs include normative sections on key rotation, identifier
  lifetime, secret-custody as the security perimeter, complementary
  (not substitutive) authoritative integrity checks, and the
  graceful-degradation property under secret compromise.

### Reference implementation
- Python: HID64 and HUUID, with unit-test suites covering the v1.0
  protocol (13 tests total, all passing).
- An end-to-end JWT + HUUID stateless tenant-validation example.

### Preserved historical material
- Earlier (pre-v1.0) Go, Rust, and Java implementations of HID64 are
  kept in `hid64/src/{go,rust,java}/` as historical artifacts; they
  use a SHA-256-only construction that predates v1.0.
- A combined HUUID+HID64 Internet-Draft (markdown) is preserved in
  `IETF/`. It has not been submitted to the IETF datatracker.
