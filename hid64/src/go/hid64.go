// Historical pre-v1.0 implementation.
//
// This file implements an earlier, SHA-256-only construction that
// predates HID64 specification v1.0. The current normative spec at
// hid64/specs/HID64-spec-v1.0.md uses HMAC-SHA256(secret, "root_id:parent_id")
// with HKDF-derived per-tenant keys; this code does NOT match that
// construction. It is preserved for reference. The canonical v1.0
// reference implementation is in hid64/src/python/hid64.py. A
// v1.0-compliant Go port is welcome as an external contribution.

package hid64

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

func getPrefix32(parentID string) uint32 {
	hash := sha256.Sum256([]byte(parentID))
	return binary.BigEndian.Uint32(hash[0:4])
}

func GenerateHID64(parentID string) (uint64, error) {
	prefix := uint64(getPrefix32(parentID))
	var suffixBytes [4]byte
	_, err := rand.Read(suffixBytes[:])
	if err != nil {
		return 0, err
	}
	suffix := uint64(binary.BigEndian.Uint32(suffixBytes[:]))
	return (prefix << 32) | suffix, nil
}

func ValidateHID64(parentID string, childID uint64) bool {
	expectedPrefix := uint64(getPrefix32(parentID))
	actualPrefix := childID >> 32
	return expectedPrefix == actualPrefix
}
