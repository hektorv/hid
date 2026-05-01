"""End-to-end demo: stateless tenant validation using HUUID + JWT.

Scenario
--------
1. A user logs in. The auth server issues a JWT whose claims include
   the user's `tenant_id` (the HUUID parent / root).
2. The server derives a per-tenant HMAC secret from a master key.
3. Resource IDs handed to the client are HUUIDs minted under that
   tenant's secret.
4. On every subsequent request, the edge / gateway re-validates the
   JWT signature, extracts `tenant_id`, re-derives the secret, and
   verifies that the resource HUUID is bound to that tenant — all
   without touching a database. Cross-tenant IDOR is rejected before
   any storage layer is consulted.

Run from `huuid/`:
    PYTHONPATH=src/python python3 examples/jwt_validation.py

This example uses only the Python standard library so it stays
runnable without extra dependencies. In production:

* Use a real JWT library (e.g. PyJWT) instead of the inline helpers
  below.
* Use HKDF (RFC 5869) for per-tenant key derivation. The
  `cryptography` package provides
  `cryptography.hazmat.primitives.kdf.hkdf.HKDF`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid

from huuid import generate_huuid, validate_huuid


# --- minimal HS256 JWT helpers (replace with PyJWT in real code) ----------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def jwt_encode(claims: dict, signing_key: bytes) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(signing_key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def jwt_decode(token: str, signing_key: bytes) -> dict:
    h, p, s = token.split(".")
    expected = hmac.new(signing_key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_decode(s), expected):
        raise ValueError("bad signature")
    claims = json.loads(_b64url_decode(p))
    if claims.get("exp", float("inf")) < time.time():
        raise ValueError("expired")
    return claims


# --- per-tenant secret derivation -----------------------------------------

def derive_tenant_secret(master_key: bytes, tenant_id: str) -> bytes:
    """Toy KDF: a single HMAC-SHA256 over the tenant id.

    In production use HKDF (RFC 5869) so the construction follows a
    standard and supports multiple derived contexts cleanly.
    """
    return hmac.new(master_key, tenant_id.encode("utf-8"), hashlib.sha256).digest()


# --- demo -----------------------------------------------------------------

MASTER_KEY = b"server-master-key-do-not-use-in-prod"
JWT_KEY    = b"jwt-signing-key-do-not-use-in-prod"


def issue_jwt(user_id: str, tenant_id: str, ttl_seconds: int = 3600) -> str:
    return jwt_encode(
        {
            "sub": user_id,
            "tenant_id": tenant_id,
            "exp": int(time.time()) + ttl_seconds,
        },
        JWT_KEY,
    )


def edge_validate(token: str, resource_id: str) -> bool:
    """Stateless gateway check: JWT signature + HUUID parent binding."""
    try:
        claims = jwt_decode(token, JWT_KEY)
    except ValueError:
        return False
    tenant_id = claims["tenant_id"]
    tenant_secret = derive_tenant_secret(MASTER_KEY, tenant_id)
    return validate_huuid(tenant_id, uuid.UUID(resource_id), tenant_secret)


def main() -> None:
    # 1. Acme user logs in; server mints a resource HUUID under their tenant.
    acme_tenant   = "tenant:acme"
    acme_token    = issue_jwt("user:42", acme_tenant)
    acme_secret   = derive_tenant_secret(MASTER_KEY, acme_tenant)
    acme_resource = generate_huuid(acme_tenant, acme_secret)

    print(f"Issued resource for acme:   {acme_resource}")

    # 2. Legitimate request from acme — JWT + own resource.
    print(f"  acme JWT + acme resource: {edge_validate(acme_token, str(acme_resource))}")

    # 3. Cross-tenant attack: evil-co user obtains acme's resource ID and
    #    tries to read it with their own (validly signed) JWT.
    evil_token = issue_jwt("user:99", "tenant:evil-co")
    print(f"  evil JWT + acme resource: {edge_validate(evil_token, str(acme_resource))}")

    # 4. Forgery without the tenant secret: random UUIDv4 fails validation
    #    (wrong version, wrong HMAC).
    print(f"  acme JWT + random UUID:   {edge_validate(acme_token, str(uuid.uuid4()))}")

    # 5. Tampered JWT (wrong signature) is rejected before HUUID is even checked.
    tampered = acme_token[:-4] + "AAAA"
    print(f"  tampered JWT:             {edge_validate(tampered, str(acme_resource))}")


if __name__ == "__main__":
    main()
