# Secure Login & User Authentication System

This repository contains a minimal interactive authentication CLI demonstrating secure coding practices, password hashing, TOTP-based multi-factor authentication (MFA), and protections against common vulnerabilities such as SQL injection.

## Features
- **Password hashing** with salted PBKDF2-HMAC-SHA256.
- **TOTP MFA** compatible with authenticator apps (RFC 6238, 6-digit codes).
- **SQLite storage** using parameterized queries to mitigate SQL injection.
- **Input validation** for safe user handling and structured logging for observability.
- **Security testing** via unit tests that cover hashing, TOTP generation/verification, and login flows.

## Getting Started
### Requirements
- Python 3.11+
- No external dependencies required.

### Setup
1. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
2. Run the application:
   ```bash
   python -m auth_system.app
   ```
   The CLI will initialize `auth.db` in the project root and guide you through registration and login with MFA.

### Usage Tips
- During registration, you will be shown a **Base32 TOTP secret**. Add it to an authenticator app (e.g., Authy, Google Authenticator) to generate login codes.
- Passwords must be at least 8 characters. Avoid reusing credentials from other services.
- The database and secrets are stored locally; delete `auth.db` to reset.

## Security Considerations
- **Credential handling:** Passwords are never stored or logged. Hashing uses 120k PBKDF2 iterations with random salts.
- **MFA verification:** TOTP codes are validated using constant-time comparisons with a small time window to tolerate clock drift.
- **SQL injection prevention:** All database operations use parameterized queries and a restricted SQLite URI.
- **Error handling:** Minimal error messages avoid revealing sensitive details.

## Testing
Run unit tests to validate cryptographic helpers and authentication logic:
```bash
python -m unittest discover tests
```

## Project Structure
```
auth_system/
  app.py           # Interactive CLI for register/login
  crypto.py        # Password hashing and TOTP helpers
  database.py      # SQLite helpers with safe defaults
report/
  report.md        # Slide-style design and testing summary
```

## License
MIT
