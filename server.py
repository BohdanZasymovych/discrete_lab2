"""
RSA server module
"""
import socket
import threading

from rsa_algorithm import (generate_key_pair,
                        encrypt_message,
                        decrypt_message)

HASH_BYTE_LENGTH = 64


class Server:
    """Class of server"""
    def __init__(self, port: int) -> None:
        self.host = "127.0.0.1"
        self.port = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username_lookup = {} # username -> (socket, public_key)
        self.public_key = None
        self.private_key = None

    def start(self):
        """Start the server"""
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # generate keys
        public_key, private_key = generate_key_pair()
        self.public_key = public_key
        self.private_key = private_key

        while True:
            c, _ = self.s.accept()
            username = c.recv(1024).decode()

            print(f"{username} tries to connect")
            self.broadcast(f"New person has joined: {username}")

            # Key exchange
            self.__send_public_key(c)
            client_public_key = self.__receive_public_key(c)
            print(client_public_key)
            self.username_lookup[username] = (c, client_public_key)

            threading.Thread(
                target=self.handle_client,
                args=(
                    c,
                ),
            ).start()

    def __send_public_key(self, c: socket):
        """Sends public key to the client"""
        encryption_exponent, mod = self.public_key

        encryption_exponent_byte_length = (encryption_exponent.bit_length()+7) // 8
        mod_byte_length = (mod.bit_length()+7) // 8

        header = encryption_exponent_byte_length.to_bytes(4, 'big') + mod_byte_length.to_bytes(4, 'big')
        encryption_exponent = encryption_exponent.to_bytes(encryption_exponent_byte_length, 'big')
        mod = mod.to_bytes(mod_byte_length, 'big')

        c.sendall(header+encryption_exponent+mod)

    def __receive_public_key(self, c: socket) -> tuple:
        """Receives public key from the client"""
        encryption_exponent_byte_length = int.from_bytes(c.recv(4), 'big')
        mod_byte_length = int.from_bytes(c.recv(4), 'big')

        encryption_exponent = int.from_bytes(c.recv(encryption_exponent_byte_length), 'big')
        mod = int.from_bytes(c.recv(mod_byte_length), 'big')

        return (encryption_exponent, mod)

    def __send_message(self, c: socket, msg: str, public_key: tuple):
        """Encrypts message and sends it to the server"""
        msg, msg_hash = encrypt_message(msg, public_key)

        msg_byte_length = (msg.bit_length()+7) // 8

        header = msg_byte_length.to_bytes(4, 'big')
        msg_hash = msg_hash.encode()
        msg = msg.to_bytes(msg_byte_length, 'big')

        c.sendall(header+msg+msg_hash)

    def __receive_message(self, c: socket) -> str:
        """Receives message from the client and decrypts it"""
        msg_byte_length = int.from_bytes(c.recv(4), 'big')

        msg = c.recv(msg_byte_length)
        msg = int.from_bytes(msg, 'big')
        msg_hash = c.recv(HASH_BYTE_LENGTH).decode()

        decrypted_msg = decrypt_message(msg, self.private_key, msg_hash)

        return decrypted_msg

    def broadcast(self, msg: str):
        """Broadcasts message to all clients"""
        for client, public_key in self.username_lookup.values():
            self.__send_message(client, msg, public_key)

    def handle_client(self, c: socket):
        """Handles client connection"""
        while True:
            msg = self.__receive_message(c)
            print(f"Received message: {msg}")

            for _, (client, public_key) in self.username_lookup.items():
                if client != c:
                    self.__send_message(client, msg, public_key)


if __name__ == "__main__":
    try:
        s = Server(9001)
        s.start()
    finally:
        s.s.close()
        print("Server closed")
