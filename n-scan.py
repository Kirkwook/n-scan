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
        hostname = get_hostname(ip_host)
        ip = ip_host
    result = [hostname, ip]
    return result

def scan_ports(ip_address, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def get_service_name(port):
    try:
        service_name = socket.getservbyport(port)
        return service_name
    except socket.error:
        return "Unknown"

def main():
    ip_host = input("Enter the target hostname or IP address:\n")
    result = get_host_ip(ip_host)
    print(result[0])
    print(result[1])
    
    #ports_to_scan = range(1, 1025)
    ports_to_scan = range(1, 25)

    open_ports = scan_ports(result[1], ports_to_scan)

    if open_ports:
        print("Open ports:")
        for port in open_ports:
            service_name = get_service_name(port)
            print(f"Port {port}: {service_name}")
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()
    #openvas.infosec.uwec.edu
    #172.26.0.50