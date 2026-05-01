# Contributing

Contributions to the HID64 and HUUID specifications and reference
implementations are welcome.

## Channels

- **Issues** — bugs, spec ambiguities, edge cases, conformance questions
- **Pull requests** — fixes, additional test vectors, v1.0-compliant
  ports for languages other than Python (Go, Rust, Java, etc.)

## Pull request guidelines

1. Fork the repository and create a feature branch
2. Add or update tests covering the change
3. Keep changes scoped — prefer separate PRs for independent concerns
4. Open the pull request with a clear description of the motivation
   and the change
5. For changes that affect the specification text, indicate explicitly
   whether the change is editorial (wording) or substantive (semantics
   or wire format); substantive changes are weighed carefully against
   v1.0 stability

## What to expect

- Reviews are best-effort by a single maintainer; response times vary
- Editorial fixes (typos, broken links, clarifications that do not
  change meaning) are typically merged quickly
- Substantive changes to v1.0 are unlikely to be accepted; new ideas
  may go into a v1.1 or v2.0 line if they accumulate

## Cross-implementation conformance

Test vectors and conformance suites for HID64 and HUUID are
particularly welcome. The reference implementation is in Python; any
port should produce identical outputs given the same `(secret,
root_id, parent_id)` inputs (HID64) or `(secret, parent_id)` inputs
(HUUID), modulo the random suffix.
