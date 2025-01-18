# SMP25519 | Secure Messaging Protocol 25519 | Python
![SMP25519 Flow Chart](./svg/smp25519_flow_chart.svg)
## Overview
SMP25519 is designed to facilitate secure communication using the X25519 key exchange, BLAKE3 hashing, and ChaCha20 encryption. It provides a straightforward interface for generating secure identities, creating handshake messages, deriving shared secrets, and encrypting/decrypting data.
## Installation
```
pip install smp25519
```
## Dependencies
To use SMP25519, install the required dependencies:
```
pip install cryptography blake3 pycryptodomex
```
## License
This package is distributed under the [Unlicense](https://choosealicense.com/licenses/unlicense/).
## Contact
For support or inquiries, contact truebreaker@proton.me.
# Examples
## Client
```python
import socket
import smp25519
import base64

def main() -> None:
    """
    Secure UDP client example using the smp25519 package.
    This script demonstrates how to establish a secure communication channel with a server using key exchange and encryption.
    """
    # Step 1: Generate client identity (private key, public key, and connection ID).
    private_key, public_key, connection_id = smp25519.generate_identity()

    # Step 2 (RECOMMENDED): Define the server's known public key (Base64 encoded).
    known_server_public_key = base64.b64decode("Vh4DBTYyDbwTqg1eZzTnuTxThscIoNQgLpxgsBCOFCU=".encode())

    # Step 3: Create a UDP socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dest_addr = ("localhost", 12000) # Server address and port.

    print(f"Secure UDP Client: Attempting connection to {dest_addr}")

    # Step 4: Send handshake message containing the client's public key.
    sock.sendto(smp25519.create_handshake_message(public_key), dest_addr)

    # Step 5: Receive and validate handshake response from the server.
    data, addr = sock.recvfrom(1024)
    if smp25519.is_handshake_message(data) == False:
        print("Error: Handshake failed. Invalid response received.")
        return
    
    # Extract the server's public key from the handshake message.
    server_public_key = smp25519.extract_public_key_from_handshake(data)

    # (RECOMMENDED) Verify the server's public key.
    if server_public_key != known_server_public_key:
        print("Error: Known server public key mismatch. Aborting connection.")
        return

    # Step 6: Derive the shared secret using the server's public key and a salt.
    # shared_secret = smp25519.derive_shared_secret(private_key, server_public_key, b"examplesalt")
    shared_secret = smp25519.derive_shared_secret(private_key, server_public_key)

    # Step 7: Exchange encrypted messages with the server.
    while True:
        # Input message from the user.
        message = input("Enter a message to send (or press Enter to retry): ").strip()
        if len(message) == 0:
            continue
        
        # Encrypt and send the message.
        encrypted_message = smp25519.encrypt_and_send_data(connection_id, message.encode(), shared_secret)
        sock.sendto(encrypted_message, dest_addr)

        # Receive and decrypt the server's response.
        data, addr = sock.recvfrom(1024)
        decrypted_message = smp25519.decrypt_received_data(data, shared_secret)
        print(f"Server response from {addr}: {decrypted_message.decode()}")

if __name__ == "__main__":
    main()
```
## Server
```python
import socket
import smp25519
import base64

def main() -> None:
    """
    Secure UDP server example using the smp25519 package.
    This script demonstrates how to establish a secure communication channel with a single
    client at a time using key exchange and encryption.
    """
    # Step 1: Generate the server's identity.
    # private_key, public_key, connection_id = smp25519.generate_identity()

    # Or use a pre-existing private key (Base64 encoded) and derive the public key.
    private_key = base64.b64decode("4Pe2QvF6zk41OWkMTqVR8e9nvwhbOEaDRti6oykaG18=".encode())
    public_key = smp25519.get_public_key_from_private(private_key)
    print(f"Server public key (Base64): {base64.b64encode(public_key).decode()}")

    # Step 2: Set up the UDP socket and bind to a port.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dest_addr = ("localhost", 12000)
    sock.bind(dest_addr)
    print(f"Secure UDP Server: Listening on {dest_addr}")

    # Variables to store client-specific connection data.
    client_connection_id: bytes = None
    client_shared_secret: bytes = None

    # Step 3: Main server loop.
    while True:
        # Receive data from a client.
        data, addr = sock.recvfrom(1024)
        print(f"Connection from {addr}")

        # Step 4: Handle handshake messages.
        if smp25519.is_handshake_message(data) == True:
            print(f"Handshake received from {addr}")

            # Extract the client's public key and generate a connection ID.
            client_public_key = smp25519.extract_public_key_from_handshake(data)
            client_connection_id = smp25519.generate_connection_id_from_public_key(client_public_key)

            # Derive a shared secret using the client's public key and a salt.
            # client_shared_secret = smp25519.derive_shared_secret(private_key, client_public_key, b"examplesalt")
            client_shared_secret = smp25519.derive_shared_secret(private_key, client_public_key)

            # Respond with the server's handshake message.
            handshake = smp25519.create_handshake_message(public_key)
            sock.sendto(handshake, addr)
            print("Handshake completed.")
            continue
        
        # Step 5: Handle encrypted messages.
        if smp25519.is_valid_data(data) == True:
            # Verify the connection ID matches the client.
            if smp25519.extract_connection_id_from_data(data) != client_connection_id:
                print(f"Error: Unknown client ID from {addr}. Ignoring message.")
                continue
            
            # Decrypt the received message.
            decrypted_message = smp25519.decrypt_received_data(data, client_shared_secret)
            print(f"Message from {addr}: {decrypted_message.decode()}")

            # Send an encrypted response back to the client.
            response_message = "Hello from Server!"
            encrypted_response = smp25519.encrypt_and_send_data(client_connection_id, response_message.encode(), client_shared_secret)
            sock.sendto(encrypted_response, addr)
            print("Response sent.")
            continue
        
        # Step 6: Handle unrecognized data.
        print(f"Error: Received unknown data from {addr}")

if __name__ == "__main__":
    main()
```