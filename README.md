# Simple messenger with RSA encryption

## Algorithm description
RSA is an asymmetric encryption algorithm. It uses two keys: public and private. Public is used to encrypt the message, and private is used to decrypt it.

Define:
- $p, q$ - prime numbers
- $n$ - modulus $n = p*q$
- $\phi(n)$ - Euler totient function of $n$
- $e$ - encryption exponent
- $d$ - decryption exponent
- $m$ - message
- $c$ - encrypted message

$e$ is choosen as integer coprime to $n$\
$d$ is choosen as inverse of e modulo $\phi(n)$. It exists since $gcd(e,n)=1$

According to Eulers's theorem:
$$x^{k\phi(n)} \equiv 1 \pmod n \Rightarrow x^{k\phi(n) + 1} \equiv x \pmod n, k \in Z$$
$$k \phi + 1 \equiv 1 \pmod{\phi(n)}$$
Since $d$ is inverse of $e$ modulo $\phi(n)$:
$$ed \equiv 1 \pmod{\phi(n)}$$
$$x^{ed} \equiv x \pmod n$$

To encrypt message it is raised to the power of $e$: $m^e \equiv c \pmod n$\
To decrypt ciphered message it is raised to the power of $d$: $c^{d} = m^{ed} \equiv m \pmod n$


## Genaration of modulus
Firstly, we generate two big prime numbers with 512 bit length. To generate a prime number we try random numbers and check, if they are prime with the probabilistic Miller-Rabin primality test. This test cannot determine, if the number is prime for sure, but if enough iterations were done, the probability of a mistake is very low, about $(\frac{1}{4})^k$, where $k$ is the number of iterations.

```python
def is_prime(x: int, k: int=100) -> bool:
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
```

Modulus $n$ is be calculated as product of two prime numbers that were found.

## Calculation of encryption and decryption exponents

The Extended Euclidean Algorithm is used to find the modular multiplicative inverse. We'll search for the inverse of a modulo $n$
```python
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
```


With the help of this function, we can conveniently find an integer that is inverted to the number by the modulo
```python
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
```

Also, functions calculating GCD and the Euler totient was implemented and are used to calculate encryption and decryption exponents
```python
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
```

```python 
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
```


Then we calculate the encryption exponent, which will be contained in the public key. The encryption exponent must satisfy two conditions:

1. $1 < a < \phi(n)$
2. $gcd(a, \phi(n)) = 1$

Value 65537 is prioritized, if it meets the conditions.

```python
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
```

## Hashing to verify integrity
A hash is used to check message integrity. It is being sent together with an encrypted message, and when a message is decrypted, its hash is calculated and compared with the sent one. If hashes match, message integrity wasn't compromised. Otherwise, the message was changed or corrupted.

The SHA256 hashing algorithm from Python's built-in module hashlib is used to calculate the hash.

```python
def calculate_message_hash(message: str) -> str:
    """Calculates message hash using sha-256 hashing algorithm"""
    return sha256(message.encode("utf-8")).hexdigest()


def verify_message_integrity(message: str, expected_message_hash: str) -> bool:
    """Verifies message integrity by calculating its hash and comparing with expected hash"""
    message_hash = sha256(message.encode("utf-8")).hexdigest()
    return message_hash == expected_message_hash
```

### Generating key pair
The functions described above are used to generate a key pair.
Firstly, two primes p and q are generated.\
Then the modulus is calculated as their product.\
Then, encryption and decryption exponents are generated.\
Public key consists of $e$ and $n$, private key consists of $d$ and $n$

```python
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
```

### Message encryption and decryption
To encrypt a message, it is first encoded to an integer. Then, it is raised to the power $e$ modulo $n$, and the result is the encrypted message, which can be decrypted only with the private key. When encrypting a message, the message hash is also calculated to be sent together with the message.

The message is raised to power $d$ modulo $n$ is being raised to decrypt it. The encrypted message is decoded from a number to a string. The hash of the decrypted message is calculated and compared with the received hash to verify message integrity.

```python
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


def decrypt_message(encrypted_message: int, private_key: tuple[int, int], message_hash: str=None) -> str:
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

    decrypted_number = binary_exponentiation(encrypted_message, decryption_exponent, mod)
    message = decode_message(decrypted_number)

    if message_hash is not None:
        if not verify_message_integrity(message, message_hash):
            raise ValueError("Message integrity check failed.")

    return message
```

## Keys exchange
When a client connects to the server, the key exchange happens. The client sends its public key and receives the server's public key. The server uses the client's public key to encrypt messages and send them to the client. Client uses the server's public key to encrypt messages and send them to the server.

## Messages exchange
To send a message, it is encrypted with the public key. Then converted to bytes. Afterwards, the byte length of a message is calculated. When sending a message over a socket, firstly, the header containing 4 bytes determining the length of the message is sent, then comes the message, and after it, its hash.

To receive a message, firstly header containing 4 bytes determining the message length are received. Then the number of bytes specified in the header is received, and 64 bytes of the hash are received. A hexadecimal string of hash computed with the SHA256 algorithm is always 64 bytes long. The message is decoded to an integer, decrypted with the private key, and its integrity is verified. 

```python
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
```

## Launch program
Run next command in the terminal in folder where file server.py is located to launch server
```bash
python3 server.py
```

Run next command in the terminal in folder where file client.py is located to launch client
```bash
python3 client.py
```

## Usage example
![](usage_example.png)
