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
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
            self.broadcast(f"new person has joined: {username}")

            # send public key to the client
            encryption_exponent, mod = self.public_key
            c.send(str(encryption_exponent).encode())
            c.send(str(mod).encode())
            print("public key sent")

            encryption_exponent = int(c.recv(1024).decode())
            mod = int(c.recv(1024).decode())
            client_public_key = (encryption_exponent, mod)
            print(client_public_key)
            self.username_lookup[username] = (c, client_public_key)

            threading.Thread(
                target=self.handle_client,
                args=(
                    c,
                ),
            ).start()

    def __send_message(self, c, msg: str, public_key: tuple):
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
