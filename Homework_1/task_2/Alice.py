import socket
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from helperFunction import generate_ecdh_key_pair

# Configuration
MY_PORT = 65433         # My listening port
TARGET_PORT = 65432      # Server's listening port
TARGET_HOST = '127.0.0.1'

# Flag to track if the party is awaiting a response
awaiting_response = False
alice_sk, alice_pk = generate_ecdh_key_pair()
shared_key = None

class ConnectionLostError(Exception):
    """Custom exception to indicate a lost connection."""
    pass


def listen_for_messages(conn, my_identity, peer_identity):
    """Continuously listen for incoming messages to act as a responder."""
    global awaiting_response, shared_key
    while True:
        if not awaiting_response:
            try:
                # Receive a message from the peer
                data = conn.recv(1024)

                if not data:
                    raise ConnectionLostError("Connection lost: No data received.")

                decoded_data = data.decode('utf-8')
                print(f"{my_identity}: Receive a message: \"{decoded_data}\" ")

            except (ConnectionResetError, BrokenPipeError, ConnectionLostError) as e:
                print(f"{my_identity}: Connection lost. Reconnecting...(Press any key to continue)")
                break
            except socket.timeout:
                continue  # No message received, continue listening


def initiate_key_exchange(conn, my_identity, peer_identity):
    """Handle initiating a key exchange when the user presses 'Y'."""
    global awaiting_response, shared_key
    awaiting_response = True

    # Print the process of key exchange
    alice_public_key_printable = alice_pk.public_bytes(
        encoding=serialization.Encoding.PEM,  # PEM format
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    message = f"Here is {my_identity}'s public key: {alice_public_key_printable}"
    conn.sendall(message.encode('utf-8'))
    print(message)

def alice():
    my_identity = "Alice"
    server_identity = "Server"
    peer_identity = "Bob"
    while True:
        try:
            # Create a listening socket
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.bind((TARGET_HOST, MY_PORT))
            listen_sock.listen()
            print(f"{my_identity}: Listening on port {MY_PORT}...")

            # Connect to the peer's listening port
            print(f"{my_identity}: Try connecting to {server_identity} to exchange messages with {peer_identity}...")
            conn_to_server = None
            while conn_to_server is None:
                try:
                    conn_to_server = socket.create_connection((TARGET_HOST, TARGET_PORT))
                    # Send client identity to the server
                    conn_to_server.sendall(my_identity.encode('utf-8'))
                except ConnectionRefusedError:
                    print(f"{my_identity}: Waiting for {server_identity} to be online...")
                    time.sleep(2)

            conn_to_server.settimeout(2)

            print(f"{my_identity}: Connected to {server_identity}.")

            # Start a thread to listen for messages relayed by the server
            listener_thread = threading.Thread(target=listen_for_messages,
                                               args=(conn_to_server, my_identity, peer_identity), daemon=True)
            listener_thread.start()

            while listener_thread.is_alive():
                proceed = input(
                    f"{my_identity}: Press 'Y' and Enter to initiate a session, or just wait to listen: \n").strip().upper()
                if proceed == "Y":
                    initiate_key_exchange(conn_to_server, my_identity, peer_identity)

            print("Alice: Connection lost. Restarting connection...")
        except ConnectionLostError:
            print(f"{my_identity}: Attempting to reconnect...")
            time.sleep(2)  # Delay before re-entering the connection phase


if __name__ == "__main__":
    alice()
