import unittest
from uuid import UUID, RFC_4122
from huuid import generate_huuid, validate_huuid, hmac_prefix

class TestHUUID(unittest.TestCase):
    def setUp(self):
        self.parent_id = "user:123"
        self.secret = b"test-secret-key"
        self.prefix_len = 3

    def test_generate_and_validate(self):
        huuid = generate_huuid(self.parent_id, self.secret, self.prefix_len)
        self.assertIsInstance(huuid, UUID)
        self.assertEqual(huuid.version, 8)
        self.assertEqual(huuid.variant, RFC_4122)
        self.assertTrue(validate_huuid(self.parent_id, huuid, self.secret, self.prefix_len))

    def test_invalid_prefix(self):
        huuid = generate_huuid(self.parent_id, self.secret)
        other_parent = "user:999"
        self.assertFalse(validate_huuid(other_parent, huuid, self.secret))

    def test_invalid_secret(self):
        huuid = generate_huuid(self.parent_id, self.secret)
        bad_secret = b"wrong-key"
        self.assertFalse(validate_huuid(self.parent_id, huuid, bad_secret))

    def test_different_prefix_lengths(self):
        for prefix_len in range(1, 7):
            huuid = generate_huuid(self.parent_id, self.secret, prefix_len)
            self.assertTrue(validate_huuid(self.parent_id, huuid, self.secret, prefix_len))

    def test_prefix_function(self):
        prefix = hmac_prefix("example", b"key", 3)
        self.assertEqual(len(prefix), 3)

    def test_uuid_format(self):
        huuid = generate_huuid(self.parent_id, self.secret)
        self.assertRegex(str(huuid), r"^[a-f0-9\-]{36}$")

    def test_invalid_prefix_length(self):
        with self.assertRaises(ValueError):
            generate_huuid(self.parent_id, self.secret, 0)
        with self.assertRaises(ValueError):
            generate_huuid(self.parent_id, self.secret, 7)

if __name__ == '__main__':
    unittest.main()
