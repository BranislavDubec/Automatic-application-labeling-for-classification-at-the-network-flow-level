""" 
    Simple UDP IPv6 echo server.

"""

__author__ = "Branislav Dubec"
__credits__ = "https://wiki.python.org/moin/UdpCommunication"
__version__ = "1.0.0"



import socket


if __name__ == "__main__":
    UDP_IP = '::1'  # Localhost
    UDP_PORT = 5005         
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((UDP_IP, UDP_PORT))

        while True:
            data, address = server_socket.recvfrom(1024) 
            print("received message: %s" % data)
            server_socket.sendto(data, address)
        