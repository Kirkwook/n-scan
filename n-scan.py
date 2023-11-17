import socket
import sys
import argparse

# Retrieves IP address based on the provided hostname
def get_ip(hostname):
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

#  Checks input and passes the output to the correct retrieval method
def get_host_ip(ip_host):
    if(ip_host[0].isalpha() == True):
        ip = get_ip(ip_host)
        hostname = ip_host
    else:
        hostname = get_hostname()
        ip = ip_host
    result = [hostname, ip]
    return result

def main():
    ip_host = input("Enter the target hostname or IP address:\n")
    result = get_host_ip(ip_host)
    print(result[0])
    print(result[1])

if __name__ == "__main__":
    main()
    #openvas.infosec.uwec.edu
    #172.26.0.50