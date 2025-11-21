"""Interactive secure login and registration CLI."""

from __future__ import annotations

import getpass
import logging
from pathlib import Path
from textwrap import dedent

from . import crypto, database

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def prompt_choice() -> str:
    print(
        dedent(
            """
            ╭──────────────────────────────────────────╮
            │   Secure Login & Authentication System   │
            │──────────────────────────────────────────│
            │1) Register                               │
            │2) Login                                  │
            │3) Exit                                   │
            ╰──────────────────────────────────────────╯
            """
        ).strip()
    )
    return input("Choose an option: ").strip()


def prompt_username() -> str:
    username = input("Username: ").strip()
    if not username:
        raise ValueError("Username cannot be empty")
    return username


def prompt_password(prompt: str = "Password: ") -> str:
    password = getpass.getpass(prompt)
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    return password


def register_user() -> None:
    try:
        username = prompt_username()
        password = prompt_password()
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            raise ValueError("Passwords do not match")
    except ValueError as exc:
        logger.error("Registration failed: %s", exc)
        return

    salt, derived_key = crypto.hash_password(password)
    credentials = crypto.encode_credentials(salt, derived_key)
    totp_secret = crypto.generate_totp_secret()

    try:
        database.store_user(username, credentials, totp_secret)
    except Exception as exc:  # pragma: no cover - sqlite uniqueness errors shown to user
        logger.error("Could not save user: %s", exc)
        return

    print("\nRegistration successful!")
    print(
        dedent(
            f"""
            ╭───────────────────────────────────────────────────╮
            │Store this TOTP secret in your authenticator app:  │
            │  {totp_secret}                 │
            │Use the app to generate 6-digit codes during login.│
            ╰───────────────────────────────────────────────────╯
            """
        ).strip()
    )


def login_user() -> None:
    try:
        username = prompt_username()
        password = prompt_password()
    except ValueError as exc:
        logger.error("Login failed: %s", exc)
        return

    record = database.get_user(username)
    if record is None:
        logger.warning("Unknown user.")
        return

    if not crypto.verify_password(password, record["credentials"]):
        logger.warning("Invalid credentials.")
        return

    token = input("Enter 6-digit TOTP code: ").strip()
    if not crypto.verify_totp(record["totp_secret"], token):
        logger.warning("Invalid or expired TOTP code.")
        return

    print("\nWelcome! Authentication successful.\n")


def main() -> None:
    database.initialize()
    db_path = Path(database.DB_PATH).resolve()
    logger.info("Database located at %s", db_path)

    while True:
        choice = prompt_choice()
        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.\n")


if __name__ == "__main__":
    main()
