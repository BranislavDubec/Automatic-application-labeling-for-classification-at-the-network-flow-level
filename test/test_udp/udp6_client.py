""" 
    Simple UDP IPv6 echo client.

"""

__author__ = "Branislav Dubec"
__credits__ = "https://wiki.python.org/moin/UdpCommunication"
__version__ = "1.0.0"

import socket

if __name__ == "__main__":
    UDP_IP   = '::1'
    UDP_PORT = 5005

    messages = ["Hello from Client 1", "Hello from Client 2", "Hello from Client 3"]
    for msg in messages:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
        
            sock.sendto(msg.encode(), (UDP_IP, UDP_PORT))
            data, server = sock.recvfrom(1024)
            print("received message: %s" % data)
        finally:
            sock.close()
    