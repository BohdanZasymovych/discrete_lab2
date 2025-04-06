import socket
import threading


def binary_exponentiation(a: int, power: int) -> int:
    """Calculates power of a using binary exponentiation algorithm"""
    pass


def calculate_a():
    pass


def calculate_b():
    pass


def generate_prime(bit_length: int) -> int:
    pass


def find_inverse(a: int, n: int) -> int:
    """find inverse of a mod n"""
    pass


def euler_totient(p, q) -> int:
    return (p-1)*(q-1)


def encode_message() -> int:
    pass


def decode_message() -> str:
    pass


def encrypt() -> str:
    pass


def decrypt() -> str:
    pass


def calculate_message_hash():
    pass


def verify_message_integrity() -> bool:
    pass

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        # create key pairs

        # exchange public keys

        # receive the encrypted secret key

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self): 
        while True:
            message = self.s.recv(1024).decode()

            # decrypt message with the secrete key

            # ... 


            print(message)

    def write_handler(self):
        while True:
            message = input()

            # encrypt message with the secrete key

            # ...

            self.s.send(message.encode())

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
