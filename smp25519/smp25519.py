from cryptography.hazmat.primitives.asymmetric import x25519 # pip install cryptography
from blake3 import blake3 # pip install blake3
from Cryptodome.Cipher import ChaCha20 # pip install pycryptodomex

SMP25519_VERSION = "1.0.0"
SMP25519_HANDSHAKE_REQUEST = b"\xff\x13"
SMP25519_HANDSHAKE_REQUEST_SIZE = len(SMP25519_HANDSHAKE_REQUEST)
SMP25519_PRIVATE_KEY_SIZE = 32
SMP25519_PUBLIC_KEY_SIZE = 32
SMP25519_CHACHA20_KEY_SIZE = 32
SMP25519_CHACHA20_NONCE_SIZE = 12
SMP25519_SHARED_SECRET_SIZE = SMP25519_CHACHA20_KEY_SIZE + SMP25519_CHACHA20_NONCE_SIZE
SMP25519_CONNECTION_ID_SIZE = 8

def get_public_key_from_private(private_key: bytes) -> bytes:
    """
    Derives the public key from the given private key.

    Args:
        private_key (bytes): The private key in bytes format, must be 32 bytes long.

    Returns:
        bytes: The corresponding public key in bytes format.

    Raises:
        AssertionError: If the private key is not 32 bytes long.
    """
    assert len(private_key) == SMP25519_PRIVATE_KEY_SIZE, f"Private key must be {SMP25519_PRIVATE_KEY_SIZE} bytes long."
    
    return x25519.X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()

def generate_connection_id_from_public_key(public_key: bytes) -> bytes:
    """
    Generates a connection ID from the given public key using the BLAKE3 hash function.

    Args:
        public_key (bytes): The public key in bytes format, must be 32 bytes long.

    Returns:
        bytes: The generated connection ID, which is 8 bytes long.

    Raises:
        AssertionError: If the public key is not 32 bytes long.
    """
    assert len(public_key) == SMP25519_PUBLIC_KEY_SIZE, f"Public key must be {SMP25519_PUBLIC_KEY_SIZE} bytes long."

    return blake3(public_key).digest(length=SMP25519_CONNECTION_ID_SIZE)

def generate_identity() -> tuple[bytes, bytes, bytes]:
    """
    Generates a unique identity consisting of a private key, public key, and connection ID.

    The connection ID is generated from the public key and must not start with the predefined
    SMP25519_HANDSHAKE_REQUEST bytes.

    Returns:
        tuple: A tuple containing the private key, public key, and connection ID, all in bytes format.
    """
    while True:
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        connection_id = generate_connection_id_from_public_key(public_key.public_bytes_raw())

        if connection_id[0:SMP25519_HANDSHAKE_REQUEST_SIZE] != SMP25519_HANDSHAKE_REQUEST:
            return (private_key.private_bytes_raw(), public_key.public_bytes_raw(), connection_id)

def create_handshake_message(public_key: bytes) -> bytes:
    """
    Creates a handshake message by prepending the SMP25519_HANDSHAKE_REQUEST to the public key.

    Args:
        public_key (bytes): The public key in bytes format, must be 32 bytes long.

    Returns:
        bytes: The handshake message containing the SMP25519_HANDSHAKE_REQUEST followed by the public key.

    Raises:
        AssertionError: If the public key is not 32 bytes long.
    """
    assert len(public_key) == SMP25519_PUBLIC_KEY_SIZE, f"Public key must be {SMP25519_PUBLIC_KEY_SIZE} bytes long."
    
    return SMP25519_HANDSHAKE_REQUEST + public_key

def is_handshake_message(data: bytes) -> bool:
    """
    Checks if the given data is a valid handshake message.

    A valid handshake message must start with the SMP25519_HANDSHAKE_REQUEST and contain a valid public key.

    Args:
        data (bytes): The data to check.

    Returns:
        bool: True if the data is a valid handshake message, False otherwise.
    """
    if len(data) < SMP25519_HANDSHAKE_REQUEST_SIZE + SMP25519_PUBLIC_KEY_SIZE:
        return False
    
    if data[0:SMP25519_HANDSHAKE_REQUEST_SIZE] == SMP25519_HANDSHAKE_REQUEST:
        return True
    
    return False

def is_valid_data(data: bytes) -> bool:
    """
    Validates the given data based on its length.

    Args:
        data (bytes): The data to validate.

    Returns:
        bool: True if the data length is greater than the SMP25519_CONNECTION_ID_SIZE, False otherwise.
    """
    if len(data) > SMP25519_CONNECTION_ID_SIZE:
        return True
    
    return False

def extract_public_key_from_handshake(handshake: bytes) -> bytes:
    """
    Extracts the public key from a valid handshake message.

    Args:
        handshake (bytes): The handshake message from which to extract the public key.

    Returns:
        bytes: The extracted public key.

    Raises:
        AssertionError: If the handshake message is not valid.
    """
    assert is_handshake_message(handshake) == True, "Forgot to check for is_handshake_message."

    return handshake[SMP25519_HANDSHAKE_REQUEST_SIZE:SMP25519_HANDSHAKE_REQUEST_SIZE + SMP25519_PUBLIC_KEY_SIZE]

def extract_connection_id_from_data(data: bytes) -> bytes:
    """
    Extracts the connection ID from the given data.

    Args:
        data (bytes): The data from which to extract the connection ID.

    Returns:
        bytes: The extracted connection ID.

    Raises:
        AssertionError: If the data length is not greater than the SMP25519_CONNECTION_ID_SIZE.
    """
    assert len(data) > SMP25519_CONNECTION_ID_SIZE, "Forgot to check for is_valid_data."

    return data[0:SMP25519_CONNECTION_ID_SIZE]

def derive_shared_secret(private_key: bytes, handshake_public_key: bytes, salt: bytes = b"") -> bytes:
    """
    Derives a shared secret using the provided private key and the public key received during the handshake.

    This function uses the X25519 key exchange algorithm to compute a shared secret from the private key
    and the public key. The resulting shared secret is then hashed using the BLAKE3 hashing function.

    Args:
        private_key (bytes): The private key in bytes format. It must be exactly 32 bytes long.
        handshake_public_key (bytes): The public key received during the handshake. It must be exactly 32 bytes long.
        salt (bytes, optional): An optional salt value to be included in the hashing process. Defaults to an empty byte string.

    Returns:
        bytes: The derived shared secret, which is 44 bytes long after hashing with BLAKE3.

    Raises:
        AssertionError: If the private key or handshake public key is not exactly 32 bytes long.
    """
    assert len(private_key) == SMP25519_PRIVATE_KEY_SIZE, f"Private key must be {SMP25519_PRIVATE_KEY_SIZE} bytes long."
    assert len(handshake_public_key) == SMP25519_PUBLIC_KEY_SIZE, f"Handshake public key must be {SMP25519_PUBLIC_KEY_SIZE} bytes long."
    
    private_key_a = x25519.X25519PrivateKey.from_private_bytes(private_key)
    public_key_b = x25519.X25519PublicKey.from_public_bytes(handshake_public_key)

    shared_secret = blake3(private_key_a.exchange(public_key_b) + b"SMP25519" + salt).digest(length=SMP25519_SHARED_SECRET_SIZE)

    return shared_secret
    
def encrypt_and_send_data(connection_id: bytes, data: bytes, shared_secret: bytes) -> bytes:
    """
    Encrypts the given data using the shared secret and prepends the connection ID.

    Args:
        connection_id (bytes): The connection ID in bytes format, must be 8 bytes long.
        data (bytes): The data to encrypt, must not be empty.
        shared_secret (bytes): The shared secret used for encryption, must be 44 bytes long.

    Returns:
        bytes: The concatenated connection ID and encrypted data.

    Raises:
        AssertionError: If the connection ID is not 8 bytes long, if the data is empty, or if the shared secret is not 44 bytes long.
    """
    assert len(connection_id) == SMP25519_CONNECTION_ID_SIZE, f"Connection id must be {SMP25519_CONNECTION_ID_SIZE} bytes long."
    assert len(data) > 0, "You can't send nothing."
    assert len(shared_secret) == SMP25519_SHARED_SECRET_SIZE, f"Secret key must be {SMP25519_SHARED_SECRET_SIZE} bytes long."

    key = shared_secret[0:SMP25519_CHACHA20_KEY_SIZE]
    nonce = shared_secret[SMP25519_CHACHA20_KEY_SIZE:]
    cipher = ChaCha20.new(key=key, nonce=nonce)

    encrypted_data = cipher.encrypt(data)

    return connection_id + encrypted_data

def decrypt_received_data(data: bytes, secret_key: bytes) -> bytes:
    """
    Decrypts the received data using the provided secret key.

    Args:
        data (bytes): The data to decrypt, must be greater than the SMP25519_CONNECTION_ID_SIZE.
        secret_key (bytes): The secret key used for decryption, must be 44 bytes long.

    Returns:
        bytes: The decrypted data.

    Raises:
        AssertionError: If the data length is not greater than the SMP25519_CONNECTION_ID_SIZE or if the secret key is not 44 bytes long.
    """
    assert len(data) > SMP25519_CONNECTION_ID_SIZE, "You can't receive nothing."
    assert len(secret_key) == SMP25519_SHARED_SECRET_SIZE, f"Secret key must be {SMP25519_SHARED_SECRET_SIZE} bytes long."

    key = secret_key[0:SMP25519_CHACHA20_KEY_SIZE]
    nonce = secret_key[SMP25519_CHACHA20_KEY_SIZE:]
    cipher = ChaCha20.new(key=key, nonce=nonce)

    decrypted_data = cipher.decrypt(data[SMP25519_CONNECTION_ID_SIZE:])

    return decrypted_data

if __name__ == "__main__":
    print(f"smp25519 {SMP25519_VERSION}")