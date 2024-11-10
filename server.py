import socket
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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

def decrypt_data(encrypted_data, key):
    key = pad_key(key)
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

    def unpad(data):
        padding_length = data[-1]
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Invalid padding length.")
        return data[:-padding_length]

    return unpad(decrypted_data)

def handle_client(client_socket, key):
    try:
        filename = client_socket.recv(1024).split(b'\n')[0].decode().strip()
        file_size = int(client_socket.recv(1024).split(b'\n')[0].decode().strip())
        logging.info(f"Receiving file: {filename} of size {file_size} bytes")

        encrypted_data = b''
        while len(encrypted_data) < file_size:
            data = client_socket.recv(1024)
            if not data:
                break
            encrypted_data += data

        logging.info(f"File {filename} received successfully.")

        # Write received encrypted file
        received_file_path = 'encrypted_received.txt.dec'
        with open(received_file_path, 'wb') as f:
            f.write(encrypted_data)

        # Decrypt the file
        decrypted_data = decrypt_data(encrypted_data, key)
        output_path = 'Output.txt'
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        logging.info(f"File decrypted and saved as {output_path}.")
    except Exception as e:
        logging.error(f"Error while handling client: {e}")
    finally:
        client_socket.close()

def start_server(host, port, key):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    logging.info(f"Server listening on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        logging.info(f"Connection from {addr}")
        handle_client(client_socket, key)

if __name__ == '__main__':
    encryption_key = b'oursecretkey12345'  # Ensure this is correctly padded for AES-128
    start_server('0.0.0.0', 5000, encryption_key)
