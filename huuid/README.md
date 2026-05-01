# HUUID

Hierarchical UUID — a UUIDv8-compatible (RFC 9562) identifier that
embeds an HMAC-SHA256-derived prefix in the UUID's `node` field,
enabling cryptographic local validation of parent-child relationships
while preserving full UUID compatibility.

## Install

```sh
pip install hierarchical-uuid
```

Requires Python ≥ 3.8. No external dependencies. The module is imported
as `huuid`; the distribution is named `hierarchical-uuid` on PyPI to
keep the naming consistent with the companion package
`hierarchical-id64`, and to avoid collision with an unrelated existing
package of the same short name.

## Quick start

```python
from huuid import generate_huuid, validate_huuid

secret    = b"replace-with-tenant-scoped-secret"
parent_id = "account:42"

huuid = generate_huuid(parent_id, secret)   # returns a standard uuid.UUID
assert validate_huuid(parent_id, huuid, secret)
print(str(huuid))   # e.g. "861f6b20-e1cc-8942-b135-e412be9faa3e"
```

For an end-to-end example combining HUUID with a JWT-based session
(stateless tenant validation at the edge, no database lookup), see the
[`jwt_validation.py` example](https://github.com/hektorv/hid/blob/main/huuid/examples/jwt_validation.py).

## Specification and security model

The full v1.0 specification — including threat model, key rotation
guidance, secret-custody as the security perimeter, complementary (not
substitutive) authoritative integrity checks, and the
graceful-degradation property under secret compromise — is at:

- [HUUID v1.0 Specification](https://github.com/hektorv/hid/blob/main/huuid/spec/HUUID-spec-v1.0.md)

## Related

For the companion compact 64-bit variant, see
[HID64](https://pypi.org/project/hierarchical-id64/).

For the umbrella repository (specifications, threat-model note,
IETF-style draft, both reference implementations), see
[github.com/hektorv/hid](https://github.com/hektorv/hid).

## License

MIT — see [LICENSE](https://github.com/hektorv/hid/blob/main/LICENSE).
