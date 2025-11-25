"""Interactive secure login and registration GUI using tkinter."""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import messagebox, ttk
from pathlib import Path

from . import crypto, database

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class AuthApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure Login & Authentication System")
        self.root.geometry("350x240")
        self.root.resizable(False, False)
        self.center_window(self.root)
        
        # Initialize database
        database.initialize()
        db_path = Path(database.DB_PATH).resolve()
        logger.info("Database located at %s", db_path)
        
        # Create main frame with top center alignment
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.place(relx=0.5, rely=0, anchor=tk.N)
        
        self.show_main_menu()
    
    def clear_frame(self):
        """Clear all widgets from main frame."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def center_window(self, window: tk.Tk | tk.Toplevel):
        """Center a window (Tk or Toplevel) on the screen."""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f"+{x}+{y}")

    def show_main_menu(self):
        """Display the main menu."""
        self.clear_frame()
        
        title = ttk.Label(
            self.main_frame,
            text="Secure Login & Authentication",
            font=("Arial", 14, "bold")
        )
        title.grid(row=0, column=0, columnspan=2, pady=(0, 30))
        
        register_btn = ttk.Button(
            self.main_frame,
            text="Register",
            command=self.show_register_form,
            width=20
        )
        register_btn.grid(row=1, column=0, columnspan=2, pady=8)
        
        login_btn = ttk.Button(
            self.main_frame,
            text="Login",
            command=self.show_login_form,
            width=20
        )
        login_btn.grid(row=2, column=0, columnspan=2, pady=8)
        
        exit_btn = ttk.Button(
            self.main_frame,
            text="Exit",
            command=self.root.quit,
            width=20
        )
        exit_btn.grid(row=3, column=0, columnspan=2, pady=8)
    
    def show_register_form(self):
        """Display the registration form."""
        self.clear_frame()
        
        title = ttk.Label(
            self.main_frame,
            text="Register New Account",
            font=("Arial", 14, "bold")
        )
        title.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Username
        ttk.Label(self.main_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5, padx=(0, 10))
        username_entry = ttk.Entry(self.main_frame, width=25)
        username_entry.grid(row=1, column=1, pady=5)
        
        # Password
        ttk.Label(self.main_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5, padx=(0, 10))
        password_entry = ttk.Entry(self.main_frame, show="*", width=25)
        password_entry.grid(row=2, column=1, pady=5)
        
        # Confirm Password
        ttk.Label(self.main_frame, text="Confirm:").grid(row=3, column=0, sticky=tk.W, pady=5, padx=(0, 10))
        confirm_entry = ttk.Entry(self.main_frame, show="*", width=25)
        confirm_entry.grid(row=3, column=1, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=(25, 0))
        
        submit_btn = ttk.Button(
            btn_frame,
            text="Register",
            command=lambda: self.register_user(
                username_entry.get(),
                password_entry.get(),
                confirm_entry.get()
            )
        )
        submit_btn.grid(row=0, column=0, padx=5)
        
        back_btn = ttk.Button(
            btn_frame,
            text="Back",
            command=self.show_main_menu
        )
        back_btn.grid(row=0, column=1, padx=5)
        
        username_entry.focus()
    
    def register_user(self, username: str, password: str, confirm: str):
        """Handle user registration."""
        try:
            # Validation
            if not username.strip():
                raise ValueError("Username cannot be empty")
            
            if len(password) < 8:
                raise ValueError("Password must be at least 8 characters long")
            
            if password != confirm:
                raise ValueError("Passwords do not match")
            
            # Hash password and generate TOTP secret
            salt, derived_key = crypto.hash_password(password)
            credentials = crypto.encode_credentials(salt, derived_key)
            totp_secret = crypto.generate_totp_secret()
            
            # Store user
            database.store_user(username.strip(), credentials, totp_secret)
            
            # Show TOTP secret in a custom dialog with copy button
            self.show_totp_secret_dialog(totp_secret)
            logger.info("User '%s' registered successfully", username.strip())
            
            self.show_main_menu()
            
        except ValueError as exc:
            messagebox.showerror("Registration Failed", str(exc))
            logger.error("Registration failed: %s", exc)
        except Exception as exc:
            messagebox.showerror("Error", f"Could not save user: {exc}")
            logger.error("Could not save user: %s", exc)
    
    def show_totp_secret_dialog(self, totp_secret: str):
        """Display TOTP secret in a dialog with copy functionality."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Registration Successful")
        dialog.geometry("350x230")
        dialog.resizable(False, False)
        self.center_window(dialog)
        dialog.transient(self.root)
        dialog.grab_set()
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Success message
        ttk.Label(
            frame,
            text="Registration Successful !",
            font=("Arial", 14, "bold")
        ).pack(pady=(0, 10))
        
        ttk.Label(
            frame,
            text="Store this TOTP secret in your authenticator app:",
            wraplength=400
        ).pack(pady=(0, 10))
        
        # TOTP secret display (readonly text widget for easy selection)
        secret_frame = ttk.Frame(frame)
        secret_frame.pack(pady=10, fill=tk.X)
        
        secret_text = tk.Text(
            secret_frame,
            height=1,
            width=32,
            font=("Courier", 11, "bold"),
            wrap=tk.WORD,
            relief=tk.SOLID,
            borderwidth=1
        )
        secret_text.pack()
        secret_text.insert("1.0", totp_secret)
        secret_text.config(state=tk.DISABLED)
        
        # Instructions
        ttk.Label(
            frame,
            text="Use the app to generate 6-digit codes during login.",
            wraplength=400
        ).pack(pady=(10, 10))
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        def copy_to_clipboard():
            dialog.clipboard_clear()
            dialog.clipboard_append(totp_secret)
            dialog.update()
            copy_btn.config(text="✓ Copied!")
            dialog.after(2000, lambda: copy_btn.config(text="Copy to Clipboard"))
        
        copy_btn = ttk.Button(
            btn_frame,
            text="Copy to Clipboard",
            command=copy_to_clipboard
        )
        copy_btn.pack(side=tk.LEFT, padx=5)
        
        close_btn = ttk.Button(
            btn_frame,
            text="Close",
            command=dialog.destroy
        )
        close_btn.pack(side=tk.LEFT, padx=5)
        
        # Wait for dialog to close
        self.root.wait_window(dialog)
    
    def show_login_form(self):
        """Display the login form."""
        self.clear_frame()
        
        title = ttk.Label(
            self.main_frame,
            text="Login",
            font=("Arial", 14, "bold")
        )
        title.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Username
        ttk.Label(self.main_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5, padx=(0, 10))
        username_entry = ttk.Entry(self.main_frame, width=25)
        username_entry.grid(row=1, column=1, pady=5)
        
        # Password
        ttk.Label(self.main_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5, padx=(0, 10))
        password_entry = ttk.Entry(self.main_frame, show="*", width=25)
        password_entry.grid(row=2, column=1, pady=5)
        
        # TOTP Code
        ttk.Label(self.main_frame, text="TOTP Code:").grid(row=3, column=0, sticky=tk.W, pady=5, padx=(0, 10))
        totp_entry = ttk.Entry(self.main_frame, width=25)
        totp_entry.grid(row=3, column=1, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=(25, 0))
        
        login_btn = ttk.Button(
            btn_frame,
            text="Login",
            command=lambda: self.login_user(
                username_entry.get(),
                password_entry.get(),
                totp_entry.get()
            )
        )
        login_btn.grid(row=0, column=0, padx=5)
        
        back_btn = ttk.Button(
            btn_frame,
            text="Back",
            command=self.show_main_menu
        )
        back_btn.grid(row=0, column=1, padx=5)
        
        username_entry.focus()
    
    def login_user(self, username: str, password: str, token: str):
        """Handle user login."""
        try:
            # Validation
            if not username.strip():
                raise ValueError("Username cannot be empty")
            
            if len(password) < 8:
                raise ValueError("Password must be at least 8 characters long")
            
            # Get user record
            record = database.get_user(username.strip())
            if record is None:
                messagebox.showerror("Login Failed", "Unknown user.")
                logger.warning("Unknown user: %s", username.strip())
                return
            
            # Verify password
            if not crypto.verify_password(password, record["credentials"]):
                messagebox.showerror("Login Failed", "Invalid password.")
                logger.warning("Invalid password for user: %s", username.strip())
                return
            
            # Verify TOTP
            if not crypto.verify_totp(record["totp_secret"], token.strip()):
                messagebox.showerror("Login Failed", "Invalid or expired TOTP code.")
                logger.warning("Invalid TOTP for user: %s", username.strip())
                return
            
            # Success
            messagebox.showinfo("Success", f"Welcome, {username}!\nAuthentication successful.")
            logger.info("User '%s' logged in successfully", username.strip())
            
            self.show_main_menu()
            
        except ValueError as exc:
            messagebox.showerror("Login Failed", str(exc))
            logger.error("Login failed: %s", exc)


def main() -> None:
    """Launch the GUI application."""
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()