# HID64

Compact 64-bit hierarchical identifier with cryptographic local validation.

HID64 binds a child identifier to an externally-authenticated `root_id`
and to its immediate `parent_id` via HMAC-SHA256, fitting the result
into a 64-bit unsigned integer suitable for `BIGINT` storage and
compact wire formats. Validation is local: a holder of the per-tenant
secret can verify hierarchical relationships without database lookups
or central coordination.

## Install

```sh
pip install hierarchical-id64
```

Requires Python ≥ 3.8 and `cryptography>=41`. The module is imported
as `hid64`; the distribution is named `hierarchical-id64` on PyPI to
keep the naming consistent with the companion package
`hierarchical-uuid`.

## Quick start

```python
from hid64 import derive_key, generate_hid64, validate_hid64

master_key = b"replace-with-securely-stored-master-key"
tenant_key = derive_key(master_key, "tenant:acme")

root_id   = "tenant:acme"   # must be authenticated externally (JWT/OAuth/etc.)
parent_id = "app:42"

hid = generate_hid64(root_id, parent_id, tenant_key)
assert validate_hid64(root_id, parent_id, hid, tenant_key)
```

## Specification and security model

The full v1.0 specification — including threat model, key rotation
guidance, secret-custody as the security perimeter, complementary (not
substitutive) authoritative integrity checks, and the
graceful-degradation property under secret compromise — is at:

- [HID64 v1.0 Specification](https://github.com/hektorv/hid/blob/main/hid64/specs/HID64-spec-v1.0.md)

## Related

For the companion 128-bit UUIDv8-compatible variant, see
[HUUID](https://pypi.org/project/hierarchical-uuid/).

For the umbrella repository (specifications, threat-model note,
IETF-style draft, both reference implementations), see
[github.com/hektorv/hid](https://github.com/hektorv/hid).

## License

MIT — see [LICENSE](https://github.com/hektorv/hid/blob/main/LICENSE).
