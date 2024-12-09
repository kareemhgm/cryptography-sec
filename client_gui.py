import socket
import ssl
import os
from tkinter import Tk, Button, Label, filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom

# Load server's public key
def load_public_key():
    with open("server_public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

# Encrypt AES key
def encrypt_aes_key(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Encrypt file
def encrypt_file(file_path, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    with open(file_path, "rb") as f:
        return encryptor.update(f.read()) + encryptor.finalize()

# Send encrypted data
def send_to_server(encrypted_data, enc_aes_key, iv):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations("server_cert.pem")

        with socket.create_connection(('127.0.0.1', 65432)) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as ssock:
                ssock.sendall(enc_aes_key)
                ssock.sendall(iv)
                ssock.sendall(encrypted_data)
                return True
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send file: {e}")
        return False

# GUI
def run_gui():
    def select_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            selected_file_label.config(text=f"Selected File: {file_path}")
            encrypt_and_send_button.config(state="normal")
            app.selected_file = file_path

    def encrypt_and_send():
        try:
            public_key = load_public_key()
            aes_key = urandom(32)
            iv = urandom(16)
            encrypted_data = encrypt_file(app.selected_file, aes_key, iv)
            enc_aes_key = encrypt_aes_key(aes_key, public_key)

            if send_to_server(encrypted_data, enc_aes_key, iv):
                messagebox.showinfo("Success", "File sent successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to process: {e}")

    app = Tk()
    app.title("Secure File Transfer")
    app.geometry("400x200")

    Label(app, text="Secure File Transfer", font=("Arial", 16)).pack(pady=10)
    Button(app, text="Select File", command=select_file).pack(pady=5)
    selected_file_label = Label(app, text="No file selected")
    selected_file_label.pack(pady=5)
    encrypt_and_send_button = Button(app, text="Encrypt and Send", state="disabled", command=encrypt_and_send)
    encrypt_and_send_button.pack(pady=10)
    app.mainloop()

if __name__ == "__main__":
    run_gui()
