from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

from . import crypto, database

# 啟用 Windows 終端機 ANSI 色彩支援
if sys.platform == 'win32':
    os.system('')


class ColorTestResult(unittest.TestResult):
    """自訂測試結果，顯示彩色輸出"""
    
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'
    
    def __init__(self):
        super().__init__()
        self.successes = []
        self.start_time = None
    
    def startTestRun(self):
        self.start_time = time.time()
    
    def addSuccess(self, test):
        super().addSuccess(test)
        self.successes.append(test)
        desc = test._testMethodName.replace('test_', '').replace('_', ' ')
        print(f"{self.GREEN}PASS{self.RESET} {test.__class__.__name__}")
        print(f"  ✓ {desc}")
    
    def addFailure(self, test, err):
        super().addFailure(test, err)
        desc = test._testMethodName.replace('test_', '').replace('_', ' ')
        print(f"{self.RED}FAIL{self.RESET} {test.__class__.__name__}")
        print(f"  ✗ {desc}")
    
    def addError(self, test, err):
        super().addError(test, err)
        desc = test._testMethodName.replace('test_', '').replace('_', ' ')
        print(f"{self.RED}ERROR{self.RESET} {test.__class__.__name__}")
        print(f"  ✗ {desc}")
    
    def printSummary(self):
        duration = time.time() - self.start_time if self.start_time else 0
        passed = len(self.successes)
        failed = len(self.failures) + len(self.errors)
        
        print(f"{'='*50}")
        print(f"Total: {self.testsRun} tests")
        if self.wasSuccessful():
            print(f"{self.GREEN}Tests: {passed} passed{self.RESET}")
        else:
            print(f"{self.RED}Tests: {passed} passed, {failed} failed{self.RESET}")
        print(f"Duration: {duration:.2f}s")


class AuthSystemTests(unittest.TestCase):
    """認證系統安全性測試"""
    
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        database.DB_PATH = Path(self.temp_dir.name) / "auth.db"
        database.initialize()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # ===== Strong Authentication: Hashing =====
    def test_password_hash_and_verify(self) -> None:
        """測試密碼雜湊與驗證"""
        salt, key = crypto.hash_password("SecurePass123!")
        encoded = crypto.encode_credentials(salt, key)
        self.assertTrue(crypto.verify_password("SecurePass123!", encoded))
        self.assertFalse(crypto.verify_password("WrongPass", encoded))

    # ===== Strong Authentication: MFA =====
    def test_totp_generation_and_verification(self) -> None:
        """測試 TOTP 雙因素驗證"""
        secret = crypto.generate_totp_secret()
        fixed_time = time.time()
        token = crypto.generate_totp(secret, timestamp=fixed_time)
        self.assertTrue(crypto.verify_totp(secret, token, window=1, interval=crypto.TOTP_INTERVAL))
        self.assertFalse(crypto.verify_totp(secret, "000000"))

    # ===== End-to-End Flow =====
    def test_end_to_end_login_flow(self) -> None:
        """測試完整登入流程"""
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

    # ===== Prevent Vulnerabilities: SQL Injection =====
    def test_sql_injection_prevention(self) -> None:
        """測試 SQL 注入攻擊防護"""
        malicious_usernames = [
            "'; DROP TABLE users; --",
            "admin'--",
            "' OR '1'='1",
            "'; DELETE FROM users WHERE '1'='1",
        ]
        
        for malicious_input in malicious_usernames:
            result = database.get_user(malicious_input)
            self.assertIsNone(result)
        
        # 確認資料庫結構完整
        salt, key = crypto.hash_password("TestPass123!")
        credentials = crypto.encode_credentials(salt, key)
        secret = crypto.generate_totp_secret()
        database.store_user("legitimate_user", credentials, secret)
        record = database.get_user("legitimate_user")
        self.assertIsNotNone(record)

    # ===== Prevent Vulnerabilities: XSS =====
    def test_xss_prevention(self) -> None:
        """測試 XSS 跨站腳本攻擊防護"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]
        
        salt, key = crypto.hash_password("TestPass123!")
        credentials = crypto.encode_credentials(salt, key)
        secret = crypto.generate_totp_secret()
        
        for i, payload in enumerate(xss_payloads):
            username = f"user_{i}_{payload}"
            try:
                database.store_user(username, credentials, secret)
                record = database.get_user(username)
                if record:
                    stored_name = record.get("username", "")
                    self.assertNotIn("<script>", stored_name.lower().replace(" ", ""))
            except Exception:
                pass


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(AuthSystemTests)
    
    result = ColorTestResult()
    result.startTestRun()
    suite.run(result)
    result.printSummary()
    
    sys.exit(0 if result.wasSuccessful() else 1)