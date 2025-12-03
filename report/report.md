# Secure Login & Authentication System

## 1. Project Name

**Secure Login & Authentication System**

A Python-based secure authentication application featuring password hashing, TOTP-based multi-factor authentication (MFA), and protection against common security vulnerabilities.

---

## 2. Goal

The goal of this project is to build a demonstrative interactive login system that implements secure coding best practices. This includes:

- Implementing secure password storage using industry-standard hashing algorithms
- Integrating Time-based One-Time Password (TOTP) for multi-factor authentication
- Preventing common security vulnerabilities such as SQL injection and XSS attacks
- Providing a modern, user-friendly GUI interface using CustomTkinter

---

## 3. Operation Steps

### 3.1 Environment Setup

1. Ensure Python 3.11+ is installed on your system.
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. Install the required dependency:
   ```bash
   pip install customtkinter
   ```

### 3.2 Running the Application

Launch the GUI application by executing:
```bash
python -m auth_system.app
```

### 3.3 User Registration

1. Click the **Register** button on the main menu.
2. Enter a username (cannot be empty).
3. Enter a password (minimum 8 characters).
4. Confirm the password.
5. Upon successful registration, a TOTP secret will be displayed.
6. Copy the TOTP secret and add it to an authenticator app (e.g., Google Authenticator, Authy).

### 3.4 User Login

1. Click the **Login** button on the main menu.
2. Enter your registered username and password.
3. Open your authenticator app and enter the 6-digit TOTP code.
4. If all credentials are valid, login will be successful.

### 3.5 Running Security Tests

Execute the test suite to verify security measures:
```bash
python -m auth_system.test
```

The tests cover password hashing, TOTP verification, SQL injection prevention, and XSS prevention.

---

## 4. Conclusion

### What I Learned

Through this project, I gained valuable knowledge and hands-on experience in several key areas of secure software development:

1. **Password Security**: I learned the importance of never storing plaintext passwords. Using PBKDF2-HMAC-SHA256 with random salts and a high iteration count (120,000) makes brute-force attacks computationally expensive.

2. **Multi-Factor Authentication (MFA)**: Implementing RFC 6238-compliant TOTP taught me how time-based tokens work and why they significantly enhance security by requiring something the user *knows* (password) and something they *have* (authenticator device).

3. **SQL Injection Prevention**: By using parameterized queries instead of string interpolation, I understood how to protect database operations from malicious input that could compromise data integrity.

4. **XSS Prevention**: Input validation and proper encoding are essential to prevent cross-site scripting attacks, especially when building web-facing applications.

5. **Secure Coding Practices**: I learned to minimize error message details to avoid information leakage, use constant-time comparison for sensitive data, and implement structured logging for security event monitoring.

6. **GUI Development**: Using CustomTkinter allowed me to create a modern, visually appealing interface while maintaining focus on the underlying security implementation.

This project reinforced the principle that security should be considered from the design phase, not as an afterthought. Building secure systems requires understanding potential attack vectors and implementing multiple layers of defense.
