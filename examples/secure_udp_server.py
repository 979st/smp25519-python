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