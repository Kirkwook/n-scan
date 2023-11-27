import socket
import sys
import argparse
import ping3
from tqdm import tqdm

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
    for port in tqdm(ports):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
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
    
def ping_host(host):
    try:
        ping = ping3.Ping(timeout=2)  # Set timeout value (in seconds)
        response = ping.ping(host)
        if response is not None:
            print(f"Ping to {host} successful. Latency: {response} ms")
        else:
            print(f"Ping to {host} failed.")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    ip_host = input("Enter the target hostname or IP address:\n")
    result = get_host_ip(ip_host)
    print(result[0])
    print(result[1])
    
    ping_host(result[1])
    
    ports_to_scan = range(1, 1025)

    open_ports = scan_ports(result[1], ports_to_scan)
    ports_list = []

    if open_ports:
        print("Open ports:")
        for port in open_ports:
            service_name = get_service_name(port)
            print(f"Port {port}: {service_name}")
            found_port = [port, service_name]
            ports_list.append(found_port)
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()
    #openvas.infosec.uwec.edu
    #172.26.0.50