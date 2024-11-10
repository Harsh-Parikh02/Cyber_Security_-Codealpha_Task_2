import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import logging

# Set up logging to audit file
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.FileHandler("audit.log"),
    logging.StreamHandler()
])

def pad_key(key):
    if len(key) == 16 or len(key) == 24 or len(key) == 32:
        return key
    elif len(key) < 16:
        return key.ljust(16, b'\0')
    elif len(key) < 24:
        return key.ljust(24, b'\0')
    else:
        return key.ljust(32, b'\0')

def encrypt_data(data, key):
    key = pad_key(key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    def pad(data):
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length]) * padding_length

    padded_data = pad(data)
    encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def write_encrypted_file(file_path, encrypted_data):
    encrypted_file_path = 'encrypted_sent.txt.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)
    logging.info(f"Encrypted file written as {encrypted_file_path}.")
    return encrypted_file_path

def send_file(file_path, server_host, server_port, key):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    encrypted_data = encrypt_data(file_data, key)
    encrypted_file_path = write_encrypted_file(file_path, encrypted_data)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))

    client_socket.sendall(os.path.basename(encrypted_file_path).encode() + b'\n')
    client_socket.sendall(str(len(encrypted_data)).encode() + b'\n')
    client_socket.sendall(encrypted_data)

    logging.info(f"File {file_path} sent successfully.")
    client_socket.close()

if __name__ == '__main__':
    file_to_send = 'input.txt'
    encryption_key = b'oursecretkey12345'  # Ensure this is correctly padded for AES-128
    send_file(file_to_send, '127.0.0.1', 5000, encryption_key)
