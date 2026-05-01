from hid64 import derive_key, generate_hid64, validate_hid64

master_key = b"replace-with-securely-stored-master-key"
tenant_key = derive_key(master_key, "tenant:acme")

root_id = "tenant:acme"      # must be authenticated externally
parent_id = "app:42"

hid = generate_hid64(root_id, parent_id, tenant_key)
print("Generated HID64:", hid)
print("Valid?", validate_hid64(root_id, parent_id, hid, tenant_key))
