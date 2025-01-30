# FlightCode Encryption Tool

**FlightCode** is a secure and user-friendly file encryption and decryption tool, built using AES-GCM encryption. It is available in both GUI and CLI versions, catering to different user preferences.

---

## 🛠 Features

### GUI Version (`flightcodeDesk.py`)
- Intuitive graphical interface built with **Tkinter**.
- Simple file selection for encryption and decryption.
- Password protection with visibility toggle.
- Success and error notifications for user guidance.

### CLI Version (`flightcode.py`)
- Interactive command-line interface for advanced users.
- File listing for easy selection from the current directory.
- AES-GCM encryption and decryption with password input.
- Aesthetic enhancements using **pyfiglet** and **colorama**.

---

# 🔍 How FlightCode Works

## Core Functionality
**FlightCode** is a file encryption and decryption tool that secures your files using **AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)**. Here's how it works:

---

## 1. Encryption Process

1. **Password-Based Key Derivation**:
   - A cryptographic key is derived from your password using **Argon2**, a secure key derivation function. This strengthens weak passwords.
   - A random **salt** is generated to ensure unique key generation for every operation.

2. **File Encryption**:
   - The tool reads the file content to be encrypted.
   - A random **nonce** (number used once) is generated, ensuring the encryption output is unique even for the same password.
   - The file is encrypted using **AES-GCM**, which provides:
     - **Confidentiality**: Data is protected from unauthorized access.
     - **Integrity**: Ensures the data hasn’t been tampered with.

3. **Output File**:
   - The encrypted file is saved with an additional extension (`.hee`).
   - The encrypted file contains:
     - The **salt**.
     - The **nonce**.
     - The **authentication tag** (used to verify integrity).
     - The **encrypted content**.

---

## 2. Decryption Process

1. **Password Validation**:
   - The tool reads the salt and nonce from the encrypted file.
   - The password is used to regenerate the cryptographic key.

2. **Data Integrity Check**:
   - The **authentication tag** is verified to ensure the file hasn't been tampered with.
   - If the tag check fails (e.g., due to a wrong password or corrupted file), the process is aborted.

3. **File Decryption**:
   - The encrypted content is decrypted back to its original form using the regenerated key.
   - The decrypted file is saved, typically with its original extension, or by removing the `.hee` suffix.

---

## User Interfaces

- **GUI Version (`flightcodeDesk.py`)**:
  - A graphical interface built with **Tkinter**.
  - Allows file selection, password input, and encryption/decryption actions with ease.
  - Ideal for users unfamiliar with command-line tools.

- **CLI Version (`flightcode.py`)**:
  - A command-line interface with interactive menus.
  - Lists available files and allows users to select, encrypt, or decrypt files directly from the terminal.

---

## Security Features

1. **AES-GCM Encryption**:
   - Combines encryption and integrity verification.
   - Ensures data confidentiality and protects against unauthorized modifications.

2. **Argon2 Key Derivation**:
   - Strengthens weak passwords by making brute-force attacks computationally expensive.

3. **Randomized Nonce and Salt**:
   - Prevents identical plaintexts from producing identical ciphertexts, even with the same password.

---

By leveraging strong encryption practices, **FlightCode** ensures your files remain secure while offering both simplicity and flexibility through its GUI and CLI options.


## 🚀 How to Use

### GUI Version (`flightcodeDesk.py`)
1. Run the script:
   ```bash
   python flightcodeDesk.py
Use the intuitive graphical interface to perform encryption or decryption:
Encrypt a File: Select a file, enter a password, and click "Encrypt."
Decrypt a File: Select a file, enter the password used during encryption, and click "Decrypt."
CLI Version (flightcode.py)
Run the script:
   ```bash
    python flightcode.py
```
Follow the menu options:
1. Encrypt a File:
View the list of files in the current directory.
Select the file by entering the corresponding number.
Enter a password to encrypt the file.
2. Decrypt a File:
View the list of files in the current directory.
Select the encrypted file by entering the corresponding number.
Enter the password used during encryption.
3. Exit: Close the program.
Both versions will notify you of the success or failure of each operation.

## 📦 Requirements

Ensure the following dependencies are installed:

- `cryptography`
- `argon2-cffi`
- `pyfiglet`
- `colorama`

The CLI version automatically installs missing packages upon execution.

---


> ⚠️ **Important**: Keep your passwords safe. Files cannot be decrypted without the correct password.

---

## 📝 Author

Developed by **Bell**  
GitHub: [github.com/Bell-O](https://github.com/Bell-O)

---

## 📜 License

This project is licensed under the Bell Software License (BSL). See the LICENSE file for details.
