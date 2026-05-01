# HUUID – Hierarchical UUID (UUIDv8-Compatible)  
**Specification v1.0 (Stable)**

---

## 1. Abstract

**HUUID** (Hierarchical UUID) is a 128-bit identifier format based on UUIDv8 ([RFC 9562](https://datatracker.ietf.org/doc/html/rfc9562)). It allows deterministic derivation of child resource identifiers from a parent ID using **HMAC-SHA256**, preserving hierarchy and enabling local validation without centralized coordination.

It preserves **UUID compatibility**, **fixed-length storage**, and **local structural validation**.

---

## 2. Motivation

Distributed systems, APIs, and multi-tenant applications need:

- Hierarchical identifiers with structural validation  
- Compatibility with standard UUID libraries  
- Protection against structure inference or ID forgery  
- Support for stateless, decentralized ID generation

HUUID encodes HMAC-derived prefixes in the `node` field of UUIDv8, while preserving standard UUID semantics and layout.

---

## 3. Identifier Structure (128 bits)

| UUID Field                | Bits | UUIDv8 Usage             | HUUID Purpose                                 |
|--------------------------|------|--------------------------|-----------------------------------------------|
| `time_low`               | 32   | Custom/Random/Timestamp  | Random (entropy; no time leakage)             |
| `time_mid`               | 16   | Custom/Random/Timestamp  | Random                                        |
| `time_hi_and_version`    | 16   | Bits 12–15 = `1000`      | UUIDv8 marker + 12 bits random                |
| `clock_seq_hi_reserved`  | 8    | Bits 6–7 = `10` variant  | RFC4122-compliant, remaining 6 bits random    |
| `clock_seq_low`          | 8    | Random                   | Random                                        |
| `node`                   | 48   | Usually MAC or random    | `[HMAC prefix (N bytes)] + [Random suffix]`   |

📌 **Note on byte order**:
UUIDs follow a **mixed-endian layout**:
- The fields `time_low`, `time_mid`, and `time_hi_and_version` are encoded in **little-endian**
- The `clock_seq` and `node` fields are in **big-endian**
- The embedded HMAC prefix is stored in `node` using **big-endian order**

---

## 4. Generation Algorithm

```python
import hmac, hashlib, os
from uuid import UUID, RFC_4122

def hmac_prefix(parent_id: str, secret: bytes, length: int = 3) -> bytes:
    # parent_id is expected to be a previously authenticated and validated root or parent identifier
    return hmac.new(secret, parent_id.encode('utf-8'), hashlib.sha256).digest()[:length]

def generate_huuid(parent_id: str, secret: bytes, prefix_len: int = 3) -> UUID:
    prefix = hmac_prefix(parent_id, secret, prefix_len)
    suffix = os.urandom(6 - prefix_len)

    rand_12bits = int.from_bytes(os.urandom(2), 'big') & 0x0FFF
    time_hi_version = (0x8 << 12) | rand_12bits

    clock_seq_hi_variant = (0b10 << 6) | (os.urandom(1)[0] & 0x3F)

    uuid_bytes = (
        os.urandom(4) +                           # time_low
        os.urandom(2) +                           # time_mid
        time_hi_version.to_bytes(2, 'big') +      # time_hi_and_version
        bytes([clock_seq_hi_variant]) +           # clock_seq_hi_reserved
        os.urandom(1) +                           # clock_seq_low
        prefix + suffix                           # node
    )
    return UUID(bytes=uuid_bytes)
```

---

## 5. Validation

```python
def validate_huuid(parent_id: str, uuid_obj: UUID, secret: bytes, prefix_len: int = 3) -> bool:
    if uuid_obj.version != 8 or uuid_obj.variant != RFC_4122:
        return False
    expected = hmac_prefix(parent_id, secret, prefix_len)
    return uuid_obj.bytes[-6:][:prefix_len] == expected
```

---

## 6. Security Considerations

| Threat                        | Mitigation                                  |
|------------------------------|---------------------------------------------|
| Hierarchy inference           | Prefix derived via HMAC (not reversible)    |
| Sibling collisions            | Random suffix ≥ 24 bits of entropy          |
| Forging children under parent | Requires secret key for valid HMAC          |
| Parent ID leakage             | Hidden via keyed derivation                 |

### 🔐 Key Management

- HMAC keys must be **cryptographically secure**, ≥128 bits
- Recommend using **per-tenant keys** derived via `HKDF`
- Rotate keys carefully — affects future validation (see "Key rotation, identifier validity, and trust boundaries" below)
- Never embed keys in client code or public APIs

Example:

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_tenant_key(master_key: bytes, tenant_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=tenant_id.encode(),
        backend=default_backend()
    ).derive(master_key)
```

### Key rotation, identifier validity, and trust boundaries

A HUUID validates only under the secret used to generate it. Rotating
the per-tenant secret therefore invalidates all HUUIDs minted under
previous secrets. Implementations SHOULD ensure that the operational
lifetime of issued HUUIDs does not exceed the rotation period of the
secret under which they were emitted, unless an overlap window of
historical secrets is explicitly maintained at the validator.

Embedding a key-generation indicator in the identifier (to enable
unbounded lifetimes across rotations) is **not specified by this
version of the protocol**. Such a scheme is bounded by the bit budget
allocated to versioning and trades entropy in the HMAC prefix or
random suffix for rotation history depth; in HUUID's 48-bit `node`
field this trade-off is particularly tight.

**Confidentiality of the secret is the security perimeter.** All
schemes — hard rotation, soft rotation with overlap, or key-generation
versioning — assume the secret has not been disclosed. A leaked secret
allows retroactive forgery of any identifier minted under it;
rotation limits only the temporal blast radius. Implementations
operating in high-confidentiality contexts MUST treat secret custody
(HSM/KMS storage, non-persistence of derived keys, audit logging that
never captures key material) as the primary control.

**HUUID validation is a complement to, not a replacement for,
authoritative integrity checks.** Local validation rejects
cross-parent and unauthenticated identifiers cheaply at the edge,
before storage is consulted. Authoritative checks — referential
integrity, ownership constraints, revocation — remain the
responsibility of the system of record.

**Failure mode under secret compromise.** Disclosure of the per-tenant
secret invalidates the local validation property: an attacker with the
secret can mint identifiers indistinguishable from legitimate ones at
the HMAC layer. Crucially, however, the system does not enter an
undefined or insecure state — it degrades to the operational baseline
of any non-cryptographic identifier scheme (UUIDv4, ULID, plain
opaque IDs), where authority rests entirely on the storage layer.
Existing referential integrity, ownership, and revocation checks
remain in force; only the cheap edge-side filter is lost. Recovery
proceeds by rotating the compromised secret, after which newly minted
identifiers regain local validation. This graceful-degradation
property holds **only if** the authoritative checks at the system of
record are continuously active in production, not engaged solely as a
fallback after compromise detection.

---

# Security and Access Authorization

## **First-Level Authentication:**
The first level of the hierarchy (e.g., project_id) **must be authenticated and authorized** using a trusted mechanism before use to ensure the user has access to the relevant resources.

Recommended mechanisms include:

- **JWT (JSON Web Tokens)**
- **OAuth 2.0 / OpenID Connect**
- **API Keys**
- **Client Certificates**
- **HMAC**
- **Role-Based Access Control (RBAC)**
- **Device-Based Authentication**
- **Multi-Factor Authentication (MFA)**
- **Biometric Authentication**

Use an opaque, random parent_id (e.g., UUIDv4 or UUIDv8) as the root identifier in a hierarchy. This prevents enumeration, enables consistent HMAC derivation, and improves security guarantees for hierarchical ID generation.

### **Recommendation:**
Using a combination of these mechanisms can improve security, depending on the specific needs of the application and the risk level associated with the resources.

---

## 7. Usage Patterns

| Use Case                  | Prefix (bytes) | Suffix (bytes) | Notes                         |
|---------------------------|----------------|----------------|-------------------------------|
| Multi-tenant applications | 3              | 3              | Balanced                      |
| Log identifiers           | 2              | 4              | More randomness, less hierarchy |
| High cardinality siblings | 2              | 4–5            | Reduces collisions            |

---

## 8. UUID Compatibility

| Property                  | HUUID          |
|---------------------------|----------------|
| UUIDv8                    | ✅              |
| RFC 4122 Variant          | ✅              |
| Compatible with UUID libs | ✅              |
| Storable as UUID          | ✅              |
| Supports local validation | ✅              |
| Carries hierarchy         | ✅ (in `node`)  |

---

## 9. Example

```python
parent_id = "account:42"
secret = b"super-secret-key"
huuid = generate_huuid(parent_id, secret)
print(str(huuid))
# Example output: '861f6b20-e1cc-8942-b135-e412be9faa3e'

validate_huuid("account:42", huuid, b"super-secret-key")
# Output: True
```

---

## 10. Status

- v1.0 stable, May 2025; public release April 2026
- Python reference implementation available; HUUID has no other language ports in v1.0
- v1.0-compliant ports for Go, Rust, Java, and other languages are welcome as external contributions

---

## 11. License

MIT
