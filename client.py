"""
RSA client module
"""

import random
import socket
import threading
import random


def modular_exponentiation(a: int, power: int, mod: int) -> int:
    """Calculates modulo of power of a using binary exponentiation algorithm"""
    res = 1
    while power > 0:
        if power & 1:
            res = res*a % mod
        a = a**2 % mod
        power >>= 1
    return res


def calculate_encryption_exponent():
    """Calculates encryption exponent a"""
    pass


def calculate_decryption_exponent():
    """Calculates encryption exponent b"""
    pass


def is_prime(x: int, k: int) -> bool:
    """Checks if number x is prime with probability of correct result >= 1-(1/4)^k"""

    if x&1 == 0:
        return False

    exponent = 0
    mod = x
    x -= 1

    while x&1 == 0:
        x >>= 1
        exponent += 1

    multiplier = x

    for i in random.sample(range(2, mod-1), k):

        cur = pow(i, multiplier, mod)
        if cur in (1, mod-1):
            continue

        for _ in range(exponent-1):
            cur = pow(cur, 2, mod)
            if cur == 1:
                print(1)
                return False
            if cur == mod-1:
                break
        else:
            print(2)
            return False

    return True


def generate_prime(bit_length: int) -> int:
    pass


def genarate_prime_pair():
    pass


def find_inverse(a: int, n: int) -> int:
    """Finds inverse of a mod n"""
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

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
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

# if __name__ == "__main__":
#     cl = Client("127.0.0.1", 9001, "b_g")
#     cl.init_connection()
