# Secure Login & Authentication System

## Slide 1 – Overview
- Goal: demonstrative interactive login system with secure coding defaults.
- Language: Python 3.11, CustomTkinter for modern GUI.
- Components: GUI, SQLite store, crypto helpers (PBKDF2, TOTP).

---

## Slide 2 – Architecture & Data Flow
- User interacts with GUI (register/login) built with CustomTkinter.
- Database layer (`database.py`) initialized with safe pragmas; all queries parameterized.
- Crypto layer (`crypto.py`) handles salts, hashing, Base32 secrets, and TOTP generation/verification.
- App layer (`app.py`) validates input, limits error leakage, and logs security-relevant events.
- Test module (`test.py`) provides comprehensive security testing with colored output.
- Data stored locally in `auth.db` (username, hashed credentials, TOTP secret, timestamps).

---

## Slide 3 – Security Measures
- **Password hashing:** PBKDF2-HMAC-SHA256 with 16-byte random salts and 120k iterations.
- **MFA:** RFC 6238-compliant 6-digit TOTPs validated with constant-time comparison and ±1 interval drift allowance.
- **SQL injection:** SQLite URI in restricted mode plus parameterized statements; no string interpolation.
- **XSS prevention:** Input validation and proper encoding to prevent cross-site scripting attacks.
- **Secret handling:** Passwords read via `getpass`, never logged; TOTP secrets shown once at registration.
- **Input validation:** Username non-empty, passwords >=8 chars, TOTP numeric/length checked.
- **Operational security:** Minimal error messages, structured logging, easily rotated database (`auth.db`).

---

## Slide 4 – Testing & Verification
- Run tests: `python -m auth_system.test`
- Test coverage includes:
  - **Hashing:** PBKDF2 password hashing and verification.
  - **MFA:** TOTP generation/verification including drift window.
  - **End-to-end:** Complete register/login flow with isolated temp DB.
  - **SQL Injection:** Malicious query attempts are safely handled.
  - **XSS Prevention:** Script injection payloads are properly sanitized.
- Manual checks:
  - Attempt login with wrong password/OTP to confirm rejection.
  - Inspect `auth.db` to verify hashed credentials and secrets are not plaintext.

---

## Slide 5 – How to Extend Safely
- Swap SQLite for PostgreSQL/MySQL via parameterized queries and least-privilege DB roles.
- Add account lockout/backoff to slow brute force attempts.
- Provide QR codes for TOTP onboarding and backup recovery codes.
- Integrate input/output encoding for web frontends to prevent XSS.
- Automate static analysis and dependency scanning in CI.
