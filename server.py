import socket
import ssl
import os
import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Save RSA keys
def save_keys(private_key, public_key):
    with open("server_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("server_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Decrypt AES key
def decrypt_aes_key(enc_key, private_key):
    return private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Decrypt file data
def decrypt_file(encrypted_data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Encrypt and save metadata
def save_metadata(metadata, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_metadata = encryptor.update(json.dumps(metadata).encode()) + encryptor.finalize()
    with open("metadata.json.enc", "wb") as f:
        f.write(encrypted_metadata)

# Main server functionality
def start_server():
    private_key, public_key = generate_rsa_keys()
    save_keys(private_key, public_key)
    print("[Server] RSA keys generated and saved.")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(('127.0.0.1', 65432))
        sock.listen(5)
        print("[Server] Listening on port 65432...")

        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            print(f"[Server] Connection established with {addr}.")

            # Receive encrypted AES key
            enc_aes_key = conn.recv(256)
            aes_key = decrypt_aes_key(enc_aes_key, private_key)
            print("[Server] AES key decrypted.")

            # Receive IV and encrypted file data
            iv = conn.recv(16)
            encrypted_data = conn.recv(4096)

            # Decrypt file
            decrypted_data = decrypt_file(encrypted_data, aes_key, iv)
            with open("received_file.txt", "wb") as f:
                f.write(decrypted_data)
            print("[Server] File decrypted and saved as 'received_file.txt'.")

            # Save metadata
            metadata = {
                "filename": "received_file.txt",
                "timestamp": str(datetime.now()),
                "client_address": str(addr)
            }
            save_metadata(metadata, aes_key, iv)
            print("[Server] Metadata encrypted and saved.")

            conn.close()

if __name__ == "__main__":
    start_server()
