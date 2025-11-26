"""Interactive secure login and registration GUI using CustomTkinter."""

from __future__ import annotations

import logging
import customtkinter as ctk
from tkinter import messagebox
from pathlib import Path

from . import crypto, database

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Set appearance mode and default color theme
ctk.set_appearance_mode("dark")  # Options: "System", "Dark", "Light"
ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"


class AuthApp:
    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("Secure Login & Authentication System")
        self.root.geometry("400x360")
        self.root.resizable(False, False)
        self.center_window(self.root)
        
        # Initialize database
        database.initialize()
        db_path = Path(database.DB_PATH).resolve()
        logger.info("Database located at %s", db_path)
        
        # Create main frame with top center alignment
        self.main_frame = ctk.CTkFrame(root, corner_radius=15)
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        self.show_main_menu()
    
    def clear_frame(self):
        """Clear all widgets from main frame."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def center_window(self, window: ctk.CTk | ctk.CTkToplevel):
        """Center a window (CTk or CTkToplevel) on the screen."""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f"+{x}+{y}")

    def show_main_menu(self):
        """Display the main menu."""
        self.clear_frame()
        
        title = ctk.CTkLabel(
            self.main_frame,
            text="🔐 Secure Login & Authentication",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(pady=(20, 40))
        
        register_btn = ctk.CTkButton(
            self.main_frame,
            text="📝 Register",
            command=self.show_register_form,
            width=200,
            height=40,
            corner_radius=10,
            font=ctk.CTkFont(size=14)
        )
        register_btn.pack(pady=10)
        
        login_btn = ctk.CTkButton(
            self.main_frame,
            text="🔑 Login",
            command=self.show_login_form,
            width=200,
            height=40,
            corner_radius=10,
            font=ctk.CTkFont(size=14)
        )
        login_btn.pack(pady=10)
        
        exit_btn = ctk.CTkButton(
            self.main_frame,
            text="🚪 Exit",
            command=self.root.quit,
            width=200,
            height=40,
            corner_radius=10,
            font=ctk.CTkFont(size=14),
            fg_color="#E74C3C",
            hover_color="#C0392B"
        )
        exit_btn.pack(pady=10)
    
    def show_register_form(self):
        """Display the registration form."""
        self.clear_frame()
        
        title = ctk.CTkLabel(
            self.main_frame,
            text="📝 Register New Account",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(pady=(20, 15))
        
        # Username
        username_entry = ctk.CTkEntry(
            self.main_frame,
            placeholder_text="Username",
            width=280,
            height=40,
            corner_radius=10,
            font=ctk.CTkFont(size=13)
        )
        username_entry.pack(pady=8)
        
        # Password
        password_entry = ctk.CTkEntry(
            self.main_frame,
            placeholder_text="Password",
            show="●",
            width=280,
            height=40,
            corner_radius=10,
            font=ctk.CTkFont(size=13)
        )
        password_entry.pack(pady=8)
        
        # Confirm Password
        confirm_entry = ctk.CTkEntry(
            self.main_frame,
            placeholder_text="Confirm Password",
            show="●",
            width=280,
            height=40,
            corner_radius=10,
            font=ctk.CTkFont(size=13)
        )
        confirm_entry.pack(pady=8)
        
        # Buttons frame
        btn_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        btn_frame.pack(pady=(20, 0))
        
        submit_btn = ctk.CTkButton(
            btn_frame,
            text="✓ Register",
            command=lambda: self.register_user(
                username_entry.get(),
                password_entry.get(),
                confirm_entry.get()
            ),
            width=130,
            height=38,
            corner_radius=10,
            font=ctk.CTkFont(size=14),
            fg_color="#27AE60",
            hover_color="#1E8449"
        )
        submit_btn.pack(side="left", padx=5)
        
        back_btn = ctk.CTkButton(
            btn_frame,
            text="← Back",
            command=self.show_main_menu,
            width=130,
            height=38,
            corner_radius=10,
            font=ctk.CTkFont(size=14),
            fg_color="#7F8C8D",
            hover_color="#5D6D7E"
        )
        back_btn.pack(side="left", padx=5)
        
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
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Registration Successful")
        dialog.geometry("400x320")
        dialog.resizable(False, False)
        
        # Wait for the window to be created before centering
        dialog.after(100, lambda: self.center_window(dialog))
        dialog.transient(self.root)
        dialog.grab_set()
        
        frame = ctk.CTkFrame(dialog, corner_radius=15)
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Success message
        ctk.CTkLabel(
            frame,
            text="✅ Registration Successful!",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#27AE60"
        ).pack(pady=(20, 15))
        
        ctk.CTkLabel(
            frame,
            text="Store this TOTP secret in your authenticator app:",
            font=ctk.CTkFont(size=13),
            wraplength=380
        ).pack(pady=8)
        
        # TOTP secret display
        secret_frame = ctk.CTkFrame(frame, fg_color="#2C3E50", corner_radius=10)
        secret_frame.pack(pady=5, padx=40, fill="x")
        
        secret_label = ctk.CTkLabel(
            secret_frame,
            text=totp_secret,
            font=ctk.CTkFont(family="Courier", size=14, weight="bold"),
            text_color="#F1C40F"
        )
        secret_label.pack(pady=10, padx=10)
        
        # Instructions
        ctk.CTkLabel(
            frame,
            text="Use the app to generate 6-digit codes during login.",
            font=ctk.CTkFont(size=13),
            wraplength=380
        ).pack(pady=8)
        
        # Buttons
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=5)
        
        def copy_to_clipboard():
            dialog.clipboard_clear()
            dialog.clipboard_append(totp_secret)
            dialog.update()
            copy_btn.configure(text="✓ Copied!")
            dialog.after(2000, lambda: copy_btn.configure(text="📋 Copy to Clipboard"))
        
        copy_btn = ctk.CTkButton(
            btn_frame,
            text="📋 Copy to Clipboard",
            command=copy_to_clipboard,
            width=150,
            height=38,
            corner_radius=10,
            font=ctk.CTkFont(size=14)
        )
        copy_btn.pack(side="left", padx=5)
        
        close_btn = ctk.CTkButton(
            btn_frame,
            text="✕ Close",
            command=dialog.destroy,
            width=100,
            height=38,
            corner_radius=10,
            font=ctk.CTkFont(size=14),
            fg_color="#7F8C8D",
            hover_color="#5D6D7E"
        )
        close_btn.pack(side="left", padx=5)
        
        # Wait for dialog to close
        self.root.wait_window(dialog)
    
    def show_login_form(self):
        """Display the login form."""
        self.clear_frame()
        
        title = ctk.CTkLabel(
            self.main_frame,
            text="🔑 Login",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(pady=(20, 15))
        
        # Username
        username_entry = ctk.CTkEntry(
            self.main_frame,
            placeholder_text="Username",
            width=280,
            height=40,
            corner_radius=10,
            font=ctk.CTkFont(size=13)
        )
        username_entry.pack(pady=8)
        
        # Password
        password_entry = ctk.CTkEntry(
            self.main_frame,
            placeholder_text="Password",
            show="●",
            width=280,
            height=40,
            corner_radius=10,
            font=ctk.CTkFont(size=13)
        )
        password_entry.pack(pady=8)
        
        # TOTP Code
        totp_entry = ctk.CTkEntry(
            self.main_frame,
            placeholder_text="TOTP Code (6 digits)",
            width=280,
            height=40,
            corner_radius=10,
            font=ctk.CTkFont(size=13)
        )
        totp_entry.pack(pady=8)
        
        # Buttons frame
        btn_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        btn_frame.pack(pady=(20, 0))
        
        login_btn = ctk.CTkButton(
            btn_frame,
            text="🔓 Login",
            command=lambda: self.login_user(
                username_entry.get(),
                password_entry.get(),
                totp_entry.get()
            ),
            width=130,
            height=38,
            corner_radius=10,
            font=ctk.CTkFont(size=14),
            fg_color="#27AE60",
            hover_color="#1E8449"
        )
        login_btn.pack(side="left", padx=5)
        
        back_btn = ctk.CTkButton(
            btn_frame,
            text="← Back",
            command=self.show_main_menu,
            width=130,
            height=38,
            corner_radius=10,
            font=ctk.CTkFont(size=14),
            fg_color="#7F8C8D",
            hover_color="#5D6D7E"
        )
        back_btn.pack(side="left", padx=5)
        
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
    root = ctk.CTk()
    app = AuthApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()