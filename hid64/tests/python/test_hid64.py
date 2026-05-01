import unittest

from hid64 import derive_key, generate_hid64, get_prefix32, validate_hid64


class TestHID64(unittest.TestCase):
    def setUp(self):
        self.master_key = b"test-master-key-do-not-use-in-prod"
        self.tenant_key = derive_key(self.master_key, "tenant:acme")
        self.root_id = "tenant:acme"
        self.parent_id = "app:42"

    def test_generate_and_validate(self):
        hid = generate_hid64(self.root_id, self.parent_id, self.tenant_key)
        self.assertTrue(0 <= hid < 2**64)
        self.assertTrue(validate_hid64(self.root_id, self.parent_id, hid, self.tenant_key))

    def test_siblings_share_prefix_differ_in_suffix(self):
        a = generate_hid64(self.root_id, self.parent_id, self.tenant_key)
        b = generate_hid64(self.root_id, self.parent_id, self.tenant_key)
        self.assertEqual(a >> 32, b >> 32)
        self.assertNotEqual(a, b)

    def test_wrong_parent_fails(self):
        hid = generate_hid64(self.root_id, self.parent_id, self.tenant_key)
        self.assertFalse(validate_hid64(self.root_id, "app:99", hid, self.tenant_key))

    def test_wrong_root_fails(self):
        hid = generate_hid64(self.root_id, self.parent_id, self.tenant_key)
        self.assertFalse(validate_hid64("tenant:other", self.parent_id, hid, self.tenant_key))

    def test_wrong_secret_fails(self):
        hid = generate_hid64(self.root_id, self.parent_id, self.tenant_key)
        bad_key = derive_key(self.master_key, "tenant:other")
        self.assertFalse(validate_hid64(self.root_id, self.parent_id, hid, bad_key))

    def test_prefix_is_deterministic(self):
        p1 = get_prefix32(self.root_id, self.parent_id, self.tenant_key)
        p2 = get_prefix32(self.root_id, self.parent_id, self.tenant_key)
        self.assertEqual(p1, p2)


if __name__ == "__main__":
    unittest.main()
