""" 
    Simple TCP IPv4 echo client.

"""

__author__ = "Branislav Dubec"
__credits__ = "https://realpython.com/python-sockets/"
__version__ = "1.0.0"

import socket


if __name__ == "__main__":
    TCP_IP = '127.0.0.1'  # Localhost
    TCP_PORT = 5005
    

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((TCP_IP, TCP_PORT))
        messages = ["Hello from Client 1", "Hello from Client 2", "Hello from Client 3"]
        for msg in messages:
            client_socket.sendall(msg.encode())
            data = client_socket.recv(1024)
            print(f"Received {data!r}")
