import socket
import sys
import argparse

def get_IP(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.error as e:
        print(f"Error: {e}")
        sys.exit(1)


def main():
    print(get_IP("openvas.infosec.uwec.edu"))


if __name__ == "__main__":
    main()