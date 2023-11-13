import socket
import sys
import argparse

# Retrieves IP address based on the provided hostname
def get_IP(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.error as e:
        print(f"Error: {e}")
        sys.exit(1)

# Retrieves hostname based on the provided IP address
def get_hostname(ip_addr):
    try:
        hostname = socket.gethostbyaddr(ip_addr)
        return hostname[0]
    except socket.error as e:
        print(f"Error: {e}")
        sys.exit(1)

def main():
    ip_host = input("Enter the target hostname or IP address:\n")
    print(get_IP(ip_host))


if __name__ == "__main__":
    main()
    #openvas.infosec.uwec.edu
    #172.26.0.50