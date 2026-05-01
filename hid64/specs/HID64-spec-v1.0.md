# HID64 – Hierarchical Identifier 64-bit  
**Specification v1.0**  

---

## 1. Abstract

**HID64** is a compact, secure, and efficient 64-bit hierarchical identifier format designed for use in distributed systems. It supports deterministic and secure derivation of child identifiers from parent contexts using **HMAC-SHA256**, allowing for **local validation** of structure without requiring database lookups or coordination. Optionally, keys can be derived per tenant or namespace using **HKDF**.

HID64 assumes that any root-level identifier (`root_id`) used in ID generation has been **previously authenticated and validated** using external access control mechanisms (e.g., JWT, OAuth, RBAC).

---

## 2. Identifier Structure

The HID64 format reserves exactly 64 bits:

```
[ 32 bits HMAC prefix ] [ 32 bits random suffix ]
```

- **32-bit HMAC-derived prefix**: Provides hierarchical binding to both a validated `root_id` and the direct `parent_id`, using HMAC-SHA256. This binding ensures local verifiability and mitigates spoofing across unrelated resource trees.
- **32-bit random suffix**: Adds entropy to avoid collisions among sibling identifiers. With 32-bit randomness, the birthday paradox suggests negligible collision probability (≤1.2%) below ~100,000 siblings per parent.

---

## 3. Key Derivation (HKDF)

Keys are derived per tenant or context using HKDF:

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(master_key: bytes, context_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context_id.encode(),
        backend=default_backend()
    ).derive(master_key)
```

---

## 4. Identifier Generation

```python
import hmac, hashlib, os

def get_prefix32(root_id: str, parent_id: str, secret: bytes) -> int:
    """
    root_id must be previously authenticated (e.g. UUID or tenant ID)
    """
    context = f"{root_id}:{parent_id}"
    h = hmac.new(secret, context.encode(), hashlib.sha256)
    return int.from_bytes(h.digest()[:4], 'big')

def generate_hid64(root_id: str, parent_id: str, secret: bytes) -> int:
    prefix = get_prefix32(root_id, parent_id, secret)
    suffix = int.from_bytes(os.urandom(4), 'big')
    return (prefix << 32) | suffix
```

---

## 5. Validation

```python
def validate_hid64(root_id: str, parent_id: str, child_id: int, secret: bytes) -> bool:
    expected_prefix = get_prefix32(root_id, parent_id, secret)
    return (child_id >> 32) == expected_prefix
```

Validation is local, deterministic, and requires no external state, assuming prior validation of the `root_id`.

---

## 6. Security Considerations

| Threat                  | Mitigation                                  |
|-------------------------|----------------------------------------------|
| Spoofing                | Requires possession of secret key           |
| Parent ID inference     | HMAC prefix is not reversible               |
| Sibling collision       | 32-bit suffix allows ~4.3B unique values    |
| Secret leakage          | Use HKDF per tenant; avoid hardcoded keys   |
| Cross-root spoofing     | Prefix derivation includes `root_id`, isolating ID trees |

---

## Security and Access Authorization

### **Root Authentication Requirement**  
Before generating or validating a HID64, the **`root_id` must be authenticated** by a trusted mechanism. This step is mandatory and prevents unauthorized ID derivation across isolated domains.

Recommended mechanisms include:

- **JWT / OAuth 2.0 / OIDC**
- **HMAC challenge-response**
- **RBAC / ABAC**
- **API Keys with context binding**
- **Device or certificate-based authentication**
- **MFA, biometric factors, or trusted hardware roots**

The `root_id` is typically a **UUID (v4 or v8)** or equivalent opaque identifier with strong randomness and non-guessability.

---

### Key Management Guidelines

- Master key should be ≥128 bits and securely stored
- Use `HKDF` to derive scoped keys (e.g., per tenant or service)
- Never embed secrets in public-facing code
- Consider key rotation policies and isolated derivation trees (see "Key rotation, identifier validity, and trust boundaries" below)

### Key rotation, identifier validity, and trust boundaries

A HID64 validates only under the secret used to generate it. Rotating
the per-tenant secret therefore invalidates all HID64s minted under
previous secrets. Implementations SHOULD ensure that the operational
lifetime of issued HID64s does not exceed the rotation period of the
secret under which they were emitted, unless an overlap window of
historical secrets is explicitly maintained at the validator.

Embedding a key-generation indicator in the identifier (to enable
unbounded lifetimes across rotations) is **not specified by this
version of the protocol**. Such a scheme is bounded by the bit budget
allocated to versioning and trades entropy in the HMAC prefix or
random suffix for rotation history depth. HID64's 32+32 layout has
more headroom than HUUID's 24+24 default, but any version field still
reduces forgery resistance or sibling capacity proportionally.

**Confidentiality of the secret is the security perimeter.** All
schemes — hard rotation, soft rotation with overlap, or key-generation
versioning — assume the secret has not been disclosed. A leaked secret
allows retroactive forgery of any identifier minted under it;
rotation limits only the temporal blast radius. Implementations
operating in high-confidentiality contexts MUST treat secret custody
(HSM/KMS storage, non-persistence of derived keys, audit logging that
never captures key material) as the primary control.

**HID64 validation is a complement to, not a replacement for,
authoritative integrity checks.** Local validation rejects
cross-tree and unauthenticated identifiers cheaply at the edge,
before storage is consulted. Authoritative checks — referential
integrity, ownership constraints, revocation — remain the
responsibility of the system of record.

**Failure mode under secret compromise.** Disclosure of the per-tenant
secret invalidates the local validation property: an attacker with the
secret can mint identifiers indistinguishable from legitimate ones at
the HMAC layer. Crucially, however, the system does not enter an
undefined or insecure state — it degrades to the operational baseline
of any non-cryptographic identifier scheme (UUIDv4, BIGINT surrogate
keys, plain opaque IDs), where authority rests entirely on the storage
layer. Existing referential integrity, ownership, and revocation
checks remain in force; only the cheap edge-side filter is lost.
Recovery proceeds by rotating the compromised secret, after which
newly minted identifiers regain local validation. This
graceful-degradation property holds **only if** the authoritative
checks at the system of record are continuously active in production,
not engaged solely as a fallback after compromise detection.

---

## 7. Use Cases

- **APIs**: Encode secure resource IDs like `Tenant → App → LogEntry`
- **Databases**: Store and filter child IDs without joins
- **Filesystem**: Verify hierarchical file ownership locally
- **Cloud Systems**: Generate regional or domain-scoped resource IDs

---

## 8. Collision Probability

| Siblings per parent | Estimated collision probability |
|---------------------|----------------------------------|
| 10,000              | ~0.01%                          |
| 50,000              | ~0.3%                           |
| 100,000             | ~1.2%                           |

To support higher cardinality, increase suffix to 40–48 bits (breaking uint64 constraint).

---

## 9. Encoding Options

- Store as native `uint64` in databases or memory
- Transmit as:
  - Decimal string: `"8712345678123456789"`
  - Hex string: `hex(id)`
  - Base64URL (for URL-safe encoding)

---

## 10. Example

```python
master_key = b"super-secret-master-key"
tenant_key = derive_key(master_key, "tenant:acme")

root_id = "tenant:acme"  # Must be authenticated externally
parent_id = "app:42:log"

hid = generate_hid64(root_id, parent_id, tenant_key)

# Validate
assert validate_hid64(root_id, parent_id, hid, tenant_key)
```

---

## 11. License

MIT

---

## 12. Status

- v1.0 stable, May 2025; public release April 2026
- Python reference implementation complete
- Go, Rust, and Java implementations in this repository are pre-v1.0 and preserved as historical artifacts; v1.0-compliant ports are welcome as external contributions

---

## References

- [RFC 2104 – HMAC](https://datatracker.ietf.org/doc/html/rfc2104)  
- [RFC 5869 – HKDF](https://datatracker.ietf.org/doc/html/rfc5869)  
- [RFC 4122 – UUID](https://datatracker.ietf.org/doc/html/rfc4122)
