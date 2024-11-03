import socket
import threading

# Configuration
MY_PORT = 65432             # My listening port
TARGET_PORT_ALICE = 65433   # Alice's listening port
TARGET_PORT_BOB = 65434     # Bob's listening port
TARGET_HOST = '127.0.0.1'
clients = {}

class ConnectionLostError(Exception):
    """Custom exception to indicate a lost connection."""
    pass

def handle_client(source_client_socket, dest_client_socket, source_client_name, dest_client_name):
    """Recieves messages from a client and forwards them."""
    try:
        while True:
            data = source_client_socket.recv(1024)
            if not data:
                break
            dest_client_socket.sendall(data)
            print(f"Server: Forwarded message from {source_client_name} to {dest_client_name} ")
            print(f"Message: {data}")
    except (ConnectionResetError, BrokenPipeError, ConnectionLostError):
        print(f"{source_client_name}: Connection lost.")

    source_client_socket.close()
    dest_client_socket.close()


def server():
    my_identity = "Server"
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((TARGET_HOST, MY_PORT))
    server_socket.listen()
    print(f"{my_identity} is listening for connecitons...")

    # Accept connections from clients
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr} has been established!")

        try:
            client_socket.sendall(b'Connected to the server')
        except ConnectionResetError:
            print(f"Connection from {addr} has been lost.")
            client_socket.close()
            continue

        # Receive the client's name
        client_name = client_socket.recv(1024).decode('utf-8').strip()

        if client_name in clients:
            print(f"Duplicate connection attempt by {client_name}. Closing connection.")
            client_socket.close()
            continue

        print(f"{client_name} connected.")
        clients[client_name] = client_socket

        # When both clients are connected, start message forwarding
        if clients.get('Alice') and clients.get('Bob'):
            print("Both Alice and Bob are connected. Starting message forwarding.")
            threading.Thread(target=handle_client, args=(clients['Alice'], clients['Bob'], 'Alice', 'Bob')).start()
            threading.Thread(target=handle_client, args=(clients['Bob'], clients['Alice'], 'Bob', 'Alice')).start()

if __name__ == "__main__":
    server()
