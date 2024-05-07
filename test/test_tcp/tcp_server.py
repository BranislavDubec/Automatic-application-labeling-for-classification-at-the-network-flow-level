""" 
    Simple TCP IPv4 echo server.

"""

__author__ = "Branislav Dubec"
__credits__ = "https://realpython.com/python-sockets/"
__version__ = "1.0.0"



import socket


if __name__ == "__main__":
    TCP_IP = '127.0.0.1'  # Localhost
    TCP_PORT = 5005
    

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((TCP_IP, TCP_PORT))
        server_socket.listen()
        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(data)

    