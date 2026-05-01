// Historical pre-v1.0 implementation.
//
// This file implements an earlier, SHA-256-only construction that
// predates HID64 specification v1.0. The current normative spec at
// hid64/specs/HID64-spec-v1.0.md uses HMAC-SHA256(secret, "root_id:parent_id")
// with HKDF-derived per-tenant keys; this code does NOT match that
// construction. It is preserved for reference. The canonical v1.0
// reference implementation is in hid64/src/python/hid64.py. A
// v1.0-compliant Java port is welcome as an external contribution.

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class HID64 {

    private static final SecureRandom random = new SecureRandom();

    // Generate 32-bit prefix from parent ID (UUID or string)
    public static int getPrefix32(String parentId) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(parentId.getBytes("UTF-8"));
            ByteBuffer buffer = ByteBuffer.wrap(hash);
            return buffer.getInt(); // first 4 bytes
        } catch (Exception e) {
            throw new RuntimeException("Hash error", e);
        }
    }

    // Generate HID64 as long (prefix + random suffix)
    public static long generateHID64(String parentId) {
        int prefix = getPrefix32(parentId);
        int suffix = random.nextInt(); // 32 bits
        return ((long) prefix << 32) | (suffix & 0xFFFFFFFFL);
    }

    // Validate that child ID was derived from given parent
    public static boolean validateHID64(String parentId, long childId) {
        int expectedPrefix = getPrefix32(parentId);
        int actualPrefix = (int) (childId >>> 32);
        return expectedPrefix == actualPrefix;
    }
}
