// Historical pre-v1.0 implementation.
//
// This file implements an earlier, SHA-256-only construction that
// predates HID64 specification v1.0. The current normative spec at
// hid64/specs/HID64-spec-v1.0.md uses HMAC-SHA256(secret, "root_id:parent_id")
// with HKDF-derived per-tenant keys; this code does NOT match that
// construction. It is preserved for reference. The canonical v1.0
// reference implementation is in hid64/src/python/hid64.py. A
// v1.0-compliant Rust port is welcome as an external contribution.

use sha2::{Digest, Sha256};
use rand::Rng;

pub fn get_prefix32(parent_id: &str) -> u32 {
    let hash = Sha256::digest(parent_id.as_bytes());
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

pub fn generate_hid64(parent_id: &str) -> u64 {
    let prefix = get_prefix32(parent_id) as u64;
    let suffix: u32 = rand::thread_rng().gen();
    (prefix << 32) | suffix as u64
}

pub fn validate_hid64(parent_id: &str, child_id: u64) -> bool {
    let expected_prefix = get_prefix32(parent_id) as u64;
    let actual_prefix = child_id >> 32;
    expected_prefix == actual_prefix
}
