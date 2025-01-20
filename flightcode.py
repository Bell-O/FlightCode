import os
import subprocess
import sys
import getpass
import pyfiglet
from colorama import Fore, Style, init
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag

init(autoreset=True)

def install_and_import(package, module_name=None):
    try:
        module_name = module_name or package
        __import__(module_name)
    except ImportError:
        print(f"Installing missing package: {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"Package {package} installed successfully.")
        __import__(module_name)

install_and_import("pyfiglet")
install_and_import("colorama")
install_and_import("cryptography")
install_and_import("argon2-cffi", module_name="argon2")


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
    """
    Encrypt a file.
    """
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

        print(Fore.GREEN + f"[+] File '{file_path}' has been encrypted as '{encrypted_path}'")
    except Exception as e:
        print(Fore.RED + f"[!] Error during encryption: {e}")


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

        original_file_path = file_path.replace('.hee', '')
        with open(original_file_path, 'wb') as f:
            f.write(plaintext)

        print(Fore.GREEN + f"[+] File '{file_path}' has been decrypted as '{original_file_path}'")
    except InvalidTag:
        print(Fore.RED + "[!] Authentication failed: Invalid password or corrupted file.")
    except Exception as e:
        print(Fore.RED + f"[!] Error during decryption: {e}")

def list_files():
    """
    Lists all files in the current directory.
    """
    current_dir = os.getcwd()
    files = [f for f in os.listdir(current_dir) if os.path.isfile(os.path.join(current_dir, f))]
    
    if not files:
        print(Fore.RED + "[!] No files found in the current directory.")
        return None

    print(Fore.CYAN + "\nAvailable files:")
    for idx, file in enumerate(files):
        print(Fore.CYAN + f"  {idx + 1}. {file}")
    return files

def display_figlet():
    fig = pyfiglet.Figlet(font="slant")
    print(Fore.RED + fig.renderText("FlightCode"))
    print(Fore.YELLOW + "Your Security, My Priority by Bell (github.com/Bell-O)")

def select_file(files):
    """
    Allows the user to select a file by number.
    """
    try:
        file_index = int(input(Fore.YELLOW + "\n[?] Select a file number: ")) - 1
        if 0 <= file_index < len(files):
            return files[file_index]
        else:
            print(Fore.RED + "[!] Invalid file number. Please try again.")
            return None
    except ValueError:
        print(Fore.RED + "[!] Please enter a valid number.")
        return None

def main():
    display_figlet()

    while True:
        print(Fore.MAGENTA + "\nMenu:")
        print(Fore.CYAN + "  1. Encrypt a file (AES-GCM)")
        print(Fore.CYAN + "  2. Decrypt a file (AES-GCM)")
        print(Fore.CYAN + "  3. Exit")
        choice = input(Fore.YELLOW + "\nSelect an option: ").strip()

        if choice == '1':
            files = list_files()
            if files:
                file_path = select_file(files)
                if file_path:
                    password = getpass.getpass("Enter a password: ")
                    encrypt_file(file_path, password)
        elif choice == '2':
            files = list_files()
            if files:
                file_path = select_file(files)
                if file_path:
                    password = getpass.getpass("Enter the password: ")
                    decrypt_file(file_path, password)
        elif choice == '3':
            print(Fore.GREEN + "\n[+] Thank you for using FlightCode!")
            break
        else:
            print(Fore.RED + "\n[!] Invalid option. Please try again.")

if __name__ == "__main__":
    main()
