"""
RSA client module
"""

import socket
import threading

from rsa_algorithm import (generate_key_pair,
                        encrypt_message,
                        decrypt_message)

HASH_BYTE_LENGTH = 64


class Client:
    """Class of client"""
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.s = None
        self.server_public_key = None

        # generate keys
        public_key, private_key = generate_key_pair()
        self.public_key = public_key
        self.private_key = private_key

    def init_connection(self):
        """Initialize connection with server"""
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
            print('Connected to server')
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())
        print(f"Connected to server with username: {self.username}")

        # Key exchange
        self.server_public_key = self.__receive_public_key()
        print(f"Server public key: {self.server_public_key}")
        self.__send_public_key()
        print("Public key sent to server")

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def __send_public_key(self):
        """Sends public key to the client"""
        encryption_exponent, mod = self.public_key

        encryption_exponent_byte_length = (encryption_exponent.bit_length()+7) // 8
        mod_byte_length = (mod.bit_length()+7) // 8

        header = encryption_exponent_byte_length.to_bytes(4, 'big') + mod_byte_length.to_bytes(4, 'big')
        encryption_exponent = encryption_exponent.to_bytes(encryption_exponent_byte_length, 'big')
        mod = mod.to_bytes(mod_byte_length, 'big')

        self.s.sendall(header+encryption_exponent+mod)

    def __receive_public_key(self) -> tuple:
        """Receives public key from the client"""
        encryption_exponent_byte_length = int.from_bytes(self.s.recv(4), 'big')
        mod_byte_length = int.from_bytes(self.s.recv(4), 'big')

        encryption_exponent = int.from_bytes(self.s.recv(encryption_exponent_byte_length), 'big')
        mod = int.from_bytes(self.s.recv(mod_byte_length), 'big')

        return (encryption_exponent, mod)

    def __send_message(self, msg: str, public_key: tuple):
        """Encrypts message and sends it to the server"""
        msg, msg_hash = encrypt_message(msg, public_key)

        msg_byte_length = (msg.bit_length()+7) // 8

        header = msg_byte_length.to_bytes(4, 'big')
        msg_hash = msg_hash.encode()
        msg = msg.to_bytes(msg_byte_length, 'big')

        self.s.sendall(header+msg+msg_hash)

    def __receive_message(self) -> str:
        """Receives message from the client and decrypts it"""
        msg_byte_length = int.from_bytes(self.s.recv(4), 'big')

        msg = self.s.recv(msg_byte_length)
        msg = int.from_bytes(msg, 'big')
        msg_hash = self.s.recv(HASH_BYTE_LENGTH).decode()

        decrypted_msg = decrypt_message(msg, self.private_key, msg_hash)

        return decrypted_msg

    def read_handler(self):
        """Handler for reading messages from the server"""
        while True:
            msg = self.__receive_message()
            print(f"Received message: {msg}")

    def write_handler(self):
        """Handler for sending messages to the server"""
        while True:
            message = input(">>> ")
            self.__send_message(message, self.server_public_key)


if __name__ == "__main__":
    user = input("Enter your username: ")
    cl = Client("127.0.0.1", 9001, user)
    cl.init_connection()
