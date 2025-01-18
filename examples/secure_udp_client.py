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