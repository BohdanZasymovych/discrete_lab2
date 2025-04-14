"""
RSA client module
"""

import random
import socket
import threading


def modular_exponentiation(a: int, power: int, mod: int) -> int:
    """Calculates the modular exponentiation of a number.

    Args:
        a: The base number (integer).
        power: The exponent (integer).
        mod: The modulus (integer).

    Returns:
        The result of (a^power) % mod (integer).
    """
    res = 1
    while power > 0:
        if power & 1:
            res = res * a % mod
        a = a**2 % mod
        power >>= 1
    return res


def gcd(a: int, b: int) -> int:
    """Finds the greatest common divisor (GCD) of two integers.

    Args:
        a: The first integer.
        b: The second integer.

    Returns:
        The greatest common divisor of a and b.
    """
    while b:
        a, b = b, a % b
    return a


def calculate_encryption_exponent(phi_n: int) -> int:
    """Calculates a suitable encryption exponent 'a' for RSA.

    The encryption exponent 'a' must satisfy two conditions:
    1. 1 < a < phi_n
    2. gcd(a, phi_n) = 1

    It prioritizes the value 65537 if it meets the conditions.
    Otherwise, it randomly searches for a suitable exponent within a limited number of attempts.
    If no random exponent is found, it iterates through odd numbers and small prime numbers.

    Args:
        phi_n: The result of Euler's totient function for n (integer).

    Returns:
        A suitable encryption exponent 'a' (integer).
    """

    lower_bound = 65537

    if lower_bound >= phi_n:
        lower_bound = 3

    if lower_bound <= 65537 < phi_n and gcd(65537, phi_n) == 1:
        return 65537

    max_attempts = 100
    attempts = 0

    while attempts < max_attempts:

        a = random.randint(lower_bound, phi_n - 1)
        if a % 2 == 0:
            a += 1
            if a >= phi_n:
                a = lower_bound + (e % 2)
        if gcd(a, phi_n) == 1:
            return a

        attempts += 1
    a = lower_bound
    if a % 2 == 0:
        a += 1

    while a < phi_n:
        if gcd(a, phi_n) == 1:
            return a
        a += 2
    for small_prime in [3, 5, 7, 11, 13, 17, 19, 23]:
        if small_prime < phi_n and gcd(small_prime, phi_n) == 1:
            return small_prime


def calculate_decryption_exponent(a, phi):
    """
    Calculates the decryption exponent 'd' for RSA.
    """
    b = find_inverse(a, phi)
    return b


def is_prime(x: int, k: int) -> bool:
    """Checks if a number x is prime using a probabilistic Miller-Rabin primality test.

    The probability of a composite number being incorrectly identified as prime is at most (1/4)^k.

    Args:
        x: The number to check for primality (integer).
        k: The number of iterations to perform (integer), increasing the accuracy.

    Returns:
        True if x is likely prime, False otherwise (boolean).
    """

    if x & 1 == 0:
        return False

    exponent = 0
    mod = x
    x -= 1

    while x & 1 == 0:
        x >>= 1
        exponent += 1

    multiplier = x

    for i in random.sample(range(2, mod - 1), k):

        cur = pow(i, multiplier, mod)
        if cur in (1, mod - 1):
            continue

        for _ in range(exponent - 1):
            cur = pow(cur, 2, mod)
            if cur == 1:
                print(1)
                return False
            if cur == mod - 1:
                break
        else:
            print(2)
            return False

    return True


def is_prime_miller_rabin(n: int, k: int = 100) -> bool:
    """Checks if a number is prime using the Miller-Rabin primality test.

    Args:
        n: The number to check for primality (integer).
        k: The number of iterations (integer, higher values increase reliability). Defaults to 100.

    Returns:
        True if n is likely prime, False otherwise (boolean).
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bit_length: int) -> int:
    """Generates a random prime number of the specified bit length.

    Args:
        bit_length: The desired bit length of the prime number (integer).

    Returns:
        A randomly generated prime number with the specified bit length (integer).
    """
    lower_bound = 2 ** (bit_length - 1)
    upper_bound = 2**bit_length - 1

    while True:
        p = random.randrange(lower_bound, upper_bound, 2)

        if is_prime_miller_rabin(p):
            return p


def genarate_prime_pair(message_bit_length: int) -> tuple[int, int]:
    """Generates two distinct prime numbers p and q for RSA.

    For secure RSA, the key length (p*q) should be
    at least twice the length of the message.

    Args:
        message_bit_length: The bit length of the message to be encrypted (integer).

    Returns:
        A tuple containing two distinct prime numbers (p, q) (tuple of integers).
    """
    key_bit_length = max(2048, message_bit_length * 2)

    p_bit_length = key_bit_length // 2
    q_bit_length = key_bit_length - p_bit_length

    p = generate_prime(p_bit_length)
    q = generate_prime(q_bit_length)

    while p == q:
        q = generate_prime(q_bit_length)

    return p, q


def find_inverse(a: int, n: int) -> tuple[int, int, int]:
    """Finds the extended Euclidean Algorithm for a and n.

    Returns a tuple (gcd, s, t) such that gcd = a*s + n*t.
    If gcd == 1, then s is the modular multiplicative inverse of a modulo n.

    Args:
        a: The first integer.
        n: The second integer (modulus).

    Returns:
        A tuple containing the greatest common divisor (gcd),
        and the coefficients s and t (tuple of integers).
    """
    if n == 0:
        return (a, 1, 0)
    else:
        s2, t2, s1, t1 = 1, 0, 0, 1
        while n > 0:
            q = a // n
            r = a - n * q
            s = s2 - q * s1
            t = t2 - q * t1

            a, n = n, r
            s2, t2 = s1, t1
            s1, t1 = s, t

        return (a, s2, t2)


def modular_inverse(a: int, n: int) -> int | None:
    """Finds the modular multiplicative inverse of a modulo n.

    Returns an integer x such that (a * x) % n = 1.
    Returns None if the inverse does not exist (i.e., gcd(a, n) != 1).

    Args:
        a: The integer for which to find the inverse.
        n: The modulus.

    Returns:
        The modular multiplicative inverse of a modulo n (integer), or None if it doesn't exist.
    """
    gcd_val, x, _ = find_inverse(a, n)

    if gcd_val != 1:
        return None
    else:
        return x % n


def msg_to_number(message, alphabet_type="ukr", n=None) -> list[int]:
    """
    Converts messages into a sequence of integers for RSA.
    Args:
        message: A message line.
        alphabet_type: Alphabet type ("ukr" or "eng").
        n: The maximum value for determining the size of the block.
    Returns:
        List of integers representing the message blocks.
    """
    if alphabet_type == "ukr":
        letters_upper = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ "
        letters_lower = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя "
        max_digit = 33
    else:
        letters_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
        letters_lower = "abcdefghijklmnopqrstuvwxyz "
        max_digit = 26

    digits = "0123456789"
    punctuation = ".,!?-:;()"

    letter_to_num = {}

    for i, letter in enumerate(letters_upper):
        letter_to_num[letter] = f"{i:02}"

    for i, letter in enumerate(letters_lower):
        letter_to_num[letter] = f"{60+i:02}"

    for i, digit in enumerate(digits):
        letter_to_num[digit] = f"{40+i:02}"

    for i, punct in enumerate(punctuation):
        letter_to_num[punct] = f"{50+i:02}"

    digits_str = ""

    for char in message:
        if char in letter_to_num:
            digits_str += letter_to_num[char]
        else:
            digits_str += "99"

    if n is None:
        n = 2**2048

    n_2 = 1
    while int(str(max_digit) * n_2) < n:
        n_2 += 1
    n_2 -= 1
    block_size = n_2

    if len(digits_str) % block_size != 0:
        padding_needed = block_size - (len(digits_str) % block_size)
        digits_str += "0" * padding_needed

    blocks = [
        int(digits_str[i : i + block_size])
        for i in range(0, len(digits_str), block_size)
    ]
    return blocks


def number_to_msg(blocks, alphabet_type="ukr", block_size=None):
    """
    Converts encoded number blocks back to the original message.
    Args:
        blocks: List of integers representing encoded message blocks.
        alphabet_type: Alphabet type ("ukr" or "eng").
        block_size: The size of each block in digits.
    Returns:
        Original message as a string.
    """
    if alphabet_type == "ukr":
        letters_upper = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ "
        letters_lower = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя "
    else:
        letters_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
        letters_lower = "abcdefghijklmnopqrstuvwxyz "

    digits = "0123456789"
    punctuation = ".,!?-:;()"

    num_to_letter = {}

    for i, letter in enumerate(letters_upper):
        num_to_letter[f"{i:02}"] = letter

    for i, letter in enumerate(letters_lower):
        num_to_letter[f"{60+i:02}"] = letter

    for i, digit in enumerate(digits):
        num_to_letter[f"{40+i:02}"] = digit

    for i, punct in enumerate(punctuation):
        num_to_letter[f"{50+i:02}"] = punct

    num_to_letter["99"] = "?"

    if block_size is None:
        block_size = len(str(blocks[0]))
        if block_size % 2 != 0:
            block_size += 1

    digits_str = ""
    for block in blocks:
        block_str = str(block).zfill(block_size)
        digits_str += block_str

    while digits_str.endswith("00") and len(digits_str) > 2:
        digits_str = digits_str[:-2]

    message = ""
    for i in range(0, len(digits_str), 2):
        if i + 1 < len(digits_str):
            digit_pair = digits_str[i : i + 2]
            if digit_pair in num_to_letter:
                message += num_to_letter[digit_pair]
            else:
                message += "?"

    return message


def euler_totient(p: int, q: int) -> int:
    """Calculates Euler's totient function for two prime numbers p and q.

    For two distinct prime numbers p and q, Euler's totient function phi(n) = (p-1) * (q-1),
    where n = p * q.

    Args:
        p: The first prime number (integer).
        q: The second prime number (integer).

    Returns:
        The result of Euler's totient function for p and q (integer).
    """
    return (p - 1) * (q - 1)


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


if __name__ == "__main__":
    num = msg_to_number("1.робота - запорука безпеки?", alphabet_type="ukr")
    print(num)
    msg = number_to_msg(num, alphabet_type="ukr")
    print(msg)
