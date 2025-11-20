from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from auth_system import crypto, database


class AuthSystemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        database.DB_PATH = Path(self.temp_dir.name) / "auth.db"
        database.initialize()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_password_hash_and_verify(self) -> None:
        salt, key = crypto.hash_password("SecurePass123!")
        encoded = crypto.encode_credentials(salt, key)
        self.assertTrue(crypto.verify_password("SecurePass123!", encoded))
        self.assertFalse(crypto.verify_password("WrongPass", encoded))

    def test_totp_generation_and_verification(self) -> None:
        secret = crypto.generate_totp_secret()
        fixed_time = time.time()
        token = crypto.generate_totp(secret, timestamp=fixed_time)
        self.assertTrue(crypto.verify_totp(secret, token, window=1, interval=crypto.TOTP_INTERVAL))
        self.assertFalse(crypto.verify_totp(secret, "000000"))

    def test_end_to_end_login_flow(self) -> None:
        password = "AnotherPass123!"
        salt, key = crypto.hash_password(password)
        credentials = crypto.encode_credentials(salt, key)
        secret = crypto.generate_totp_secret()
        database.store_user("alice", credentials, secret)

        record = database.get_user("alice")
        self.assertIsNotNone(record)
        self.assertTrue(crypto.verify_password(password, record["credentials"]))

        token = crypto.generate_totp(secret)
        self.assertTrue(crypto.verify_totp(secret, token))


if __name__ == "__main__":
    unittest.main()
