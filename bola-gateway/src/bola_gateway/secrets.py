"""Print fresh keys for a .env file: `python -m bola_gateway.secrets > .env`."""

import secrets

KEY_BYTES = 32

if __name__ == "__main__":
    print(f"MASTER_KEY={secrets.token_urlsafe(KEY_BYTES)}")
    print(f"TOKEN_KEY={secrets.token_urlsafe(KEY_BYTES)}")
