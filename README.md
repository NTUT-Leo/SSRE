# Secure Login & User Authentication System

This repository contains a minimal interactive authentication GUI demonstrating secure coding practices, password hashing, TOTP-based multi-factor authentication (MFA), and protections against common vulnerabilities such as SQL injection and XSS.

## Features
- **Password hashing** with salted PBKDF2-HMAC-SHA256.
- **TOTP MFA** compatible with authenticator apps (RFC 6238, 6-digit codes).
- **SQLite storage** using parameterized queries to mitigate SQL injection.
- **XSS prevention** with input validation and proper encoding.
- **Input validation** for safe user handling and structured logging for observability.
- **Security testing** with colored output covering hashing, TOTP, SQL injection, and XSS prevention.

## Getting Started
### Requirements
- Python 3.11+
- CustomTkinter (`pip install customtkinter`)

### Setup
1. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install customtkinter
   ```
3. Run the application:
   ```bash
   python -m auth_system.app
   ```
   The GUI will initialize `auth.db` in the project root and guide you through registration and login with MFA.

### Usage Tips
- During registration, you will be shown a **Base32 TOTP secret**. Add it to an authenticator app (e.g., Authy, Google Authenticator) to generate login codes.
- Passwords must be at least 8 characters. Avoid reusing credentials from other services.
- The database and secrets are stored locally; delete `auth.db` to reset.

## Security Considerations
- **Credential handling:** Passwords are never stored or logged. Hashing uses 120k PBKDF2 iterations with random salts.
- **MFA verification:** TOTP codes are validated using constant-time comparisons with a small time window to tolerate clock drift.
- **SQL injection prevention:** All database operations use parameterized queries and a restricted SQLite URI.
- **XSS prevention:** Input validation and encoding to prevent cross-site scripting attacks.
- **Error handling:** Minimal error messages avoid revealing sensitive details.

## Testing
Run security tests with colored output:
```bash
python -m auth_system.test
```

Test coverage includes:
- Password hashing and verification
- TOTP generation and verification
- End-to-end login flow
- SQL injection prevention
- XSS prevention

## Project Structure
```
auth_system/
  app.py           # Interactive GUI using CustomTkinter
  crypto.py        # Password hashing and TOTP helpers
  database.py      # SQLite helpers with safe defaults
  test.py          # Security tests with colored output
report/
  report.md        # Slide-style design and testing summary
```

## License
MIT
