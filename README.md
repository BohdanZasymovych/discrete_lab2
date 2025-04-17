# Simple messenger with RSA encryption

## Algorithm description
RSA is asymethric encryption algorithm. It uses two keys public and private. Public is used to encrypt message and private to decrypt it.

Define:
- $p, q$ - prime numbers
- $n$ - modulus $n = p*q$
- $\phi(n)$ - euler totient function of $n$
- $e$ - encryption exponent
- $d$ - decryption exponent
- $m$ - message
- $c$ - encrypted message

We want:
$$m^e \equiv c \pmod n$$
$$c^d \equiv m \pmod n$$

According to Ferma's little theorem:
$$m^{k\phi(n)} \equiv 1 \pmod n$$
$$m^{k\phi(n) + 1} \equiv m \pmod n$$ 
where $k \in \Z$

Let $e$ be integer such that $gcd(e, \phi(n)) = 1$\
According to Besu's theorem exists such number $d$ that $de \equiv 1 \pmod{\phi(n)}$.
So to find $d$ multiplicative inverse of $e$ modulo $\phi(n)$ has to be calculated. And $de = k \phi(n) + 1$ thus $m^{de} \equiv m \pmod{\phi(n)}$



## Algorithm process
First we generate two big prime numbers with lentgth of 512 bits. To generate prime number we are trying random numbers and checking if they are prime with probabilistic Miller-Rabin primality test. This test cannot determine if number is prime for sure but, if enougth iterations were done, probability of mistake is very low about (1/4)^k where k is number of iterations.

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

Modulus n will be product of two found primes.

Then we are calculating encryption exponent which will be contained in the public key. The encryption exponent must satisfy two conditions:

1. 1 < a < phi_n
2. gcd(a, phi_n) = 1

Value 65537 is prioritized if it meets the condions.

```python
def calculate_encryption_exponent(phi_n: int) -> int:
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
To check message integrity hash is used. It is being sent together with encrypted message and when message is decrypted its hash is being calculated and compared with sent one. If hashes match message integrity wasn't compromised, othervise message was changed or was corrupted.

To calculate hash SHA256 hashing algorithm from python's built-in module hashlib is used.

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
Functions described above is used to generate key pair.
Firstly two primes p and q is generated.\
Then modulus is calculated as their product.\
Then encryption and decryption exponents are generated.\
Public key consist of e and n, private of d, n

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
To encrypt message firstly it is encoded to an integer. Then raised to power e modulo n and result is encrypted message which can be decrypted only with private key. When encrypting message hash also being calculeted to be sent together with message.

To decrypt message it is being raised to the power of d modulo n. Then encrypted message is decoded from number to string. Hash of decrypted message is being calculated and comapared with received hash to verify message integrity.

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
When client connects to the server key exchange happens. Client sends its public key and receives public key of the server. Server uses client's public key to encrypt messages and send them to the client. Client uses server's public key to encrypt messages and send them to the server.

## Messages exchange
To send message it is being encrypted with public key. Then convered to the bytes. Afterwards byte length of a message is being calculated. When sending message over a socket firstly header containing 4 bytes determining length of a message is being sent then comes message and after it its hash. Hexadecimal string of hash computed with SHA256 algorithm is always 64 bytes long.

To receive message firstly header with 4 bytes determining message length are received. Then number of bytes specified in the header are received and after it 64 bytes of the hash is received. Then message is decoded to an integer, decrypted with private key and its integrity is being verified. 

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

## Usage example
![](usage_example.png)