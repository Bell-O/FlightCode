import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag

def derive_key(password: str, salt: bytes, key_size: int = 32) -> bytes:
    if key_size not in [16, 24, 32]:
        raise ValueError("Invalid key size. AES supports 16, 24, or 32 bytes.")
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=2**16,
        parallelism=2,
        hash_len=key_size,
        type=Type.ID,
    )

def encrypt_file(file_path: str, password: str):
    try:
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = derive_key(password, salt, key_size=32)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        encrypted_path = file_path + '.hee'
        with open(encrypted_path, 'wb') as f:
            f.write(salt + nonce + encryptor.tag + ciphertext)

        messagebox.showinfo("Success", f"File encrypted successfully:\n{encrypted_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Error during encryption:\n{e}")

def decrypt_file(file_path: str, password: str):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        salt = data[:16]
        nonce = data[16:28]
        tag = data[28:44]
        ciphertext = data[44:]
        key = derive_key(password, salt, key_size=32)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        original_file_path = file_path.replace('.enc', '')
        with open(original_file_path, 'wb') as f:
            f.write(plaintext)

        messagebox.showinfo("Success", f"File decrypted successfully:\n{original_file_path}")
    except InvalidTag:
        messagebox.showerror("Error", "Authentication failed: Invalid password or corrupted file.")
    except Exception as e:
        messagebox.showerror("Error", f"Error during decryption:\n{e}")

def select_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        messagebox.showwarning("No file selected", "Please select a file.")
    return file_path

def toggle_password(entry, show_password_var):
    if show_password_var.get():
        entry.config(show="")
    else:
        entry.config(show="*")

def main_ui():
    root = tk.Tk()
    root.title("FlightCode - File Encryption Tool")
    root.geometry("400x600")
    root.configure(bg="#1a1a1a")

    # Styling
    button_style = {
        "font": ("Arial", 12),
        "relief": "flat",
        "bd": 0,
        "highlightthickness": 0,
        "activebackground": "#444",
        "activeforeground": "#fff"
    }

    def rainbow_hover(button):
        button.configure(
            font=("Arial", 12, "bold"),
            fg="#ff7576",
            bg="#2B3044",
            bd=0,
            highlightthickness=0,
            activebackground="#444",
            activeforeground="#fff"
        )

    tk.Label(
        root, text="FlightCode", font=("Arial", 36, "bold"),
        fg="#00ffcc", bg="#1a1a1a"
    ).pack(pady=30)

    tk.Label(
        root, text="Your Security, My Priority by Bell (github.com/Bell-O)",
        font=("Arial", 10), fg="#888", bg="#1a1a1a"
    ).pack(pady=5)

    def encrypt_action():
        file_path = select_file()
        if file_path:
            encrypt_window = tk.Toplevel(root)
            encrypt_window.title("Encrypt File")
            encrypt_window.configure(bg="#1a1a1a")

            tk.Label(
                encrypt_window, text="Enter Password:",
                font=("Arial", 12), fg="#fff", bg="#1a1a1a"
            ).pack(pady=10)

            password_entry = tk.Entry(
                encrypt_window, font=("Arial", 12), bg="#2B3044",
                fg="#fff", show="*", relief="flat", highlightthickness=0
            )
            password_entry.pack(pady=5)

            show_password_var = tk.BooleanVar()
            tk.Checkbutton(
                encrypt_window, text="Show Password", variable=show_password_var,
                command=lambda: toggle_password(password_entry, show_password_var),
                fg="#fff", bg="#1a1a1a", selectcolor="#333"
            ).pack(pady=5)

            tk.Button(
                encrypt_window, text="Encrypt", bg="#00b386", fg="#fff",
                command=lambda: [encrypt_file(file_path, password_entry.get()), encrypt_window.destroy()],
                **button_style
            ).pack(pady=10)

    def decrypt_action():
        file_path = select_file()
        if file_path:
            decrypt_window = tk.Toplevel(root)
            decrypt_window.title("Decrypt File")
            decrypt_window.configure(bg="#1a1a1a")

            tk.Label(
                decrypt_window, text="Enter Password:",
                font=("Arial", 12), fg="#fff", bg="#1a1a1a"
            ).pack(pady=10)

            password_entry = tk.Entry(
                decrypt_window, font=("Arial", 12), bg="#2B3044",
                fg="#fff", show="*", relief="flat", highlightthickness=0
            )
            password_entry.pack(pady=5)

            show_password_var = tk.BooleanVar()
            tk.Checkbutton(
                decrypt_window, text="Show Password", variable=show_password_var,
                command=lambda: toggle_password(password_entry, show_password_var),
                fg="#fff", bg="#1a1a1a", selectcolor="#333"
            ).pack(pady=5)

            tk.Button(
                decrypt_window, text="Decrypt", bg="#ff6600", fg="#fff",
                command=lambda: [decrypt_file(file_path, password_entry.get()), decrypt_window.destroy()],
                **button_style
            ).pack(pady=10)

    encrypt_btn = tk.Button(
        root, text="Encrypt a File", bg="#00b386", fg="#fff",
        command=encrypt_action, **button_style
    )
    encrypt_btn.pack(pady=10)

    decrypt_btn = tk.Button(
        root, text="Decrypt a File", bg="#00b386", fg="#fff",
        command=decrypt_action, **button_style
    )
    decrypt_btn.pack(pady=10)

    exit_btn = tk.Button(
        root, text="Exit", bg="#ff4d4d", fg="#fff",
        command=root.destroy, **button_style
    )
    exit_btn.pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    main_ui()
