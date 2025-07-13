import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import random
import string


def encrypt_file(input_path, password):
    backend = default_backend()

    # Generate random salt
    salt = os.urandom(16)

    # Derive 256-bit key from password + salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=backend
    )
    key = kdf.derive(password.encode())

    # Random 12-byte IV for AES-GCM
    iv = os.urandom(12)

    # Read file contents
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # Encrypt data
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=backend
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Output path: same directory, random extension
    output_path = f"{input_path}.mimir"

    # Write salt + iv + tag + ciphertext to output
    with open(output_path, 'wb') as f:
        f.write(salt)            # 16 bytes
        f.write(iv)              # 12 bytes
        f.write(encryptor.tag)   # 16 bytes (GCM tag)
        f.write(ciphertext)

    print(f"Encrypted: {input_path} -> {output_path}")

def decrypt_file(input_path, password):
    backend = default_backend()

    with open(input_path, 'rb') as f:

        # Read salt, iv, tag, ciphertext
        salt = f.read(16)
        iv = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()

    # Derive key from password + salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=backend
    )
    key = kdf.derive(password.encode())

    # Setup AES-GCM cipher for decryption
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=backend
    ).decryptor()

    # Decrypt data
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise ValueError("Decryption failed. Wrong password or corrupted file.") from e

    # Restore original filename
    dir_path = os.path.dirname(input_path)
    original_name = os.path.basename(input_path)
    new_name = original_name.replace(".mimir", "")
    output_name = f"Decrypted_{new_name}"
    output_path = os.path.join(dir_path, output_name)

    # Write decrypted data
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f"Decrypted: {input_path} -> {output_path}")

def select_file():
    filename = filedialog.askopenfilename()
    file_path_var.set(filename)

def encryption_selection():
    filepath = file_path_var.get()
    password = password_var.get()
    if not filepath or not password:
        messagebox.showerror("Error", "Please select a file and enter a password.")
        return
    
    proceed = messagebox.askyesno(
    "Warning",
    "You are about to encrypt this file.\n\n⚠️ WARNING:\n"
    "- If you lose the password, this file cannot be recovered.\n"
    "- Mimir does NOT delete the original file.\n"
    "- You are responsible for managing the encrypted and original files.\n\n"
    "Do you want to continue?"
)
    if not proceed:
        return  # Cancel the operation


    encrypt_file(filepath, password)
    messagebox.showinfo("Success", f"Encrypted {filepath}!")

def decryption_selection():
    filepath = file_path_var.get()
    password = password_var.get()
    if not filepath or not password:
        messagebox.showerror("Error", "Please select a file and enter a password.")
        return
    decrypt_file(filepath, password)
    messagebox.showinfo("Success", f"Decrypted {filepath}!")

root = tk.Tk()
root.title("Mimir - Stealth Encryptor")

file_path_var = tk.StringVar()
password_var = tk.StringVar()

tk.Label(root, text="Select File:").grid(row=0, column=0, sticky="e")
tk.Entry(root, textvariable=file_path_var, width=40).grid(row=0, column=1)
tk.Button(root, text="Browse", command=select_file).grid(row=0, column=2)

tk.Label(root, text="Password:").grid(row=1, column=0, sticky="e")
tk.Entry(root, textvariable=password_var, show="*").grid(row=1, column=1)

tk.Button(root, text="Encrypt", command=encryption_selection).grid(row=2, column=0)
tk.Button(root, text="Decrypt", command=decryption_selection).grid(row=2, column=1)

root.mainloop()
