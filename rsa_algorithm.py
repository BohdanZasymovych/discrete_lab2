"""rsa_algorithm.py"""

import random
from hashlib import sha256
from time import time

# The length of the modulus for RSA encryption/decryption.
MODULUS_BIT_LENGTH = 1024


def binary_exponentiation(a: int, power: int, mod: int | None = None) -> int:
    """Calculates the modular exponentiation of a number.

    Args:
        a: The base number (integer).
        power: The exponent (integer).
        mod: The modulus (integer).

    Returns:
        The result of (a^power) % mod (integer) if mod is None finds a^power (integer).
    """
    res = 1
    if mod is None:
        while power > 0:
            if power & 1:
                res = res * a
            a = a**2
            power >>= 1
        return res

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

    lower_bound = 65537 if phi_n <= 65537 else 3

    if lower_bound <= 65537 < phi_n and gcd(65537, phi_n) == 1:
        return 65537

    max_attempts = 100

    while max_attempts > 0:

        a = random.randint(lower_bound, phi_n - 1)
        if a % 2 == 0:
            a += 1
            if a >= phi_n:
                a = lower_bound

        if gcd(a, phi_n) == 1:
            return a

        max_attempts -= 1

    a = lower_bound

    while a < phi_n:
        if gcd(a, phi_n) == 1:
            return a
        a += 2

    # If we don't find any 'a', we try some small primes.
    for small_prime in [3, 5, 7, 11, 13, 17, 19, 23]:
        if small_prime < phi_n and gcd(small_prime, phi_n) == 1:
            return small_prime


def calculate_decryption_exponent(a, phi: int) -> int:
    """
    Calculates the decryption exponent 'd' for RSA.
    """
    b = modular_inverse(a, phi)
    return b


def is_prime(x: int, k: int = 100) -> bool:
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

    while k > 0:
        k -= 1

        i = random.randint(2, mod - 1)
        cur = pow(i, multiplier, mod)

        if cur in (1, mod - 1):
            continue

        for _ in range(exponent - 1):
            cur = pow(cur, 2, mod)
            if cur == 1:
                return False
            if cur == mod - 1:
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
    lower_bound = pow(2, bit_length - 1) + 1
    upper_bound = pow(2, bit_length) - 1

    while True:
        p = random.randrange(lower_bound, upper_bound, 2)

        if is_prime(p):
            return p


def genarate_prime_pair() -> tuple[int, int]:
    """Generates two distinct prime numbers p and q for RSA.

    For secure RSA, the key length (p*q) should be
    at least twice the length of the message.

    Args:
        message_bit_length: The bit length of the message to be encrypted (integer).

    Returns:
        A tuple containing two distinct prime numbers (p, q) (tuple of integers).
    """
    p_bit_length = MODULUS_BIT_LENGTH // 2
    q_bit_length = MODULUS_BIT_LENGTH - p_bit_length

    p = generate_prime(p_bit_length)
    q = generate_prime(q_bit_length)

    while p == q:
        q = generate_prime(q_bit_length)

    return p, q


def find_inverse(a: int, n: int) -> tuple[int, int]:
    """Finds inverse of a modulo n using extended Euclidean Algorithm for a and n.

    Returns a tuple (gcd, s) such that gcd = a*s + n*t.
    If gcd == 1, then s is the modular multiplicative inverse of a modulo n.

    Args:
        a: The first integer.
        n: The second integer (modulus).

    Returns:
        A tuple containing the greatest common divisor (gcd),
        and the coefficient s (tuple of integers).
    """
    if n == 0:
        return a, 1

    s2, t2, s1, t1 = 1, 0, 0, 1
    while n > 0:
        q = a // n
        r = a - n * q
        s = s2 - q * s1
        t = t2 - q * t1

        a, n = n, r
        s2, t2 = s1, t1
        s1, t1 = s, t

    return a, s2


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
    gcd_val, x = find_inverse(a, n)

    if gcd_val != 1:
        return None

    return x % n


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


def generate_key_pair() -> tuple[tuple[int, int], tuple[int, int]]:
    """Generates a pair of RSA keys (public and private).

    Returns:
        A tuple containing the public key (e, n) and the private key (d, n).
        Public key contains the encryption exponent 'e' and modulus 'n'.
        Private key contains the decryption exponent 'd' and modulus 'n'.
    """
    p, q = genarate_prime_pair()

    n = p * q

    phi_n = euler_totient(p, q)

    e = calculate_encryption_exponent(phi_n)

    d = calculate_decryption_exponent(e, phi_n)

    return (e, n), (d, n)


def encode_message(message: str, mod: int) -> int:
    """Encodes a message into an integer for RSA encryption."""
    number = int.from_bytes(message.encode("utf-8"))

    if number >= mod:
        raise ValueError("Message is too long.")

    return number


def decode_message(message_number: int) -> str:
    """Decodes an integer back into a string message."""
    message = message_number.to_bytes(
        (message_number.bit_length() + 7) // 8, "big"
    ).decode("utf-8", errors="ignore")

    return message


def encrypt_message(message: str, public_key: tuple[int, int]) -> tuple[int, str]:
    """Encrypts a message using the RSA public key.
    Args:
        message: The message to be encrypted (string).
        public_key: The RSA public key (tuple of integers).
        Returns:
            A tuple containing the encrypted message (integer) and the message hash (string).
    """
    encryption_exponent, mod = public_key
    message_hash = calculate_message_hash(message)

    encoded_message = encode_message(message, mod)

    encrypted_message = binary_exponentiation(encoded_message, encryption_exponent, mod)
    return encrypted_message, message_hash


def decrypt_message(
    encrypted_message: int, private_key: tuple[int, int], message_hash: str = None
) -> str:
    """Decrypts an encrypted message using the RSA private key.
    Args:
        encrypted_message: The encrypted message (integer).
        private_key: The RSA private key (tuple of integers).
        message_hash: The hash of the original message (string).
    Returns:
        The decrypted message (string).
    Raises:
        ValueError: If the message integrity check fails.
    """
    decryption_exponent, mod = private_key

    decrypted_number = binary_exponentiation(
        encrypted_message, decryption_exponent, mod
    )
    message = decode_message(decrypted_number)

    if message_hash is not None:
        if not verify_message_integrity(message, message_hash):
            raise ValueError("Message integrity check failed.")

    return message


def calculate_message_hash(message: str) -> str:
    """Calculates message hash using sha-256 hashing algorithm"""
    return sha256(message.encode("utf-8")).hexdigest()


def verify_message_integrity(message: str, expected_message_hash: str) -> bool:
    """Verifies message integrity by calculating its hash and comparing with expected hash"""
    message_hash = sha256(message.encode("utf-8")).hexdigest()
    return message_hash == expected_message_hash


if __name__ == "__main__":
    MSG = "1"
    print("Original message:", MSG)

    start_time = time()
    public, private = generate_key_pair()
    print("Public key:", public)
    print("Private key:", private)
    print()

    encrypted_msg, msg_hash = encrypt_message(MSG, public)
    print("Encrypted message:", encrypted_msg)

    decrypted_msg = decrypt_message(encrypted_msg, private, msg_hash)

    print()
    print("Decrypted message:", decrypted_msg)
    finish_time = time()
    print()
    print("Time taken:", finish_time - start_time)
