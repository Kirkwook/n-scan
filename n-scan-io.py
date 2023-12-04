import socket
import sys
import argparse
import ping3
from scapy.all import sr1, IP, TCP, ARP, Ether, srp
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
        sock.settimeout(0.05)
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
        ping = ping3.ping(host, timeout=2)  # Set timeout value (in seconds)
        if ping is not None:
            return ping
        else:
            return -1
    except Exception as e:
        print(f"An error occurred: {e}")

def test_tcp_port(ip, port, timeout=1):
    # Crafting a TCP SYN packet
    packet = IP(dst=ip) / TCP(dport=port, flags="S")

    # Sending the packet and waiting for a response
    response = sr1(packet, timeout=timeout, verbose=False)

    # Checking the response
    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x12:  # TCP SYN-ACK flag
            return True
        elif response[TCP].flags == 0x14:  # TCP RST-ACK flag
            return False
    return False

def get_mac_address(ip_address):
    # Create an ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)

    # Send the packet and capture the response
    result = srp(arp_request, timeout=3, verbose=False)[0]

    # Extract the MAC address from the response
    if result:
        return result[0][1].hwsrc
    else:
        return None

def main():
    line_count = 0
    file_path = input("Enter the filepath of the source file:\n")
    file_object = open(file_path, "r")
    file_output = open("output.txt", "w")

    filter_list = []
    protocol_name = ""
    while protocol_name != "end":
        protocol_name = input("Enter protocols to filter for (type end to exit):\n")
        if protocol_name != "end":
            filter_list.append(protocol_name)

    isExclusive = "temp"
    while isExclusive == "temp":
        isExclusive = input("Would you like exclusive port reporting? (Y/N):\n")

    file_output.write("N-SCAN NETWORK SCANNER - JOB SOURCE FILE: " + file_path + "\n")
    for lines in file_object:
        file_contents = []
        file_contents.append("\n")
        file_contents.append("----------------------------------------------------------\n")
        line_count += 1
        file_contents.append("Scanning for line " + str(line_count) + " content: " + lines.strip() + "\n")
        print("Network scan of: " + lines.strip())

        ip_host = lines.strip()
        result = get_host_ip(ip_host)
        file_contents.append("Hostname: " + result[0] + "\n")
        file_contents.append("IP Address: " + result[1] + "\n")

        ping_time = ping_host(result[1])
        if ping_time >= 0:
            file_contents.append("Ping response time: " + str(ping_time) + " ms\n")
        else:
            file_contents.append("Ping response time was unsuccessful.\n")

        ports_to_scan = range(1, 1025)
        open_ports = scan_ports(result[1], ports_to_scan)
        file_contents.append("Open ports found: " + str(len(open_ports)) + "\n")

        for port in open_ports:
            is_open = test_tcp_port(result[1], port)
            if (is_open):
                file_contents.append("Test packet to port " + str(port) + " returned successfully."+"\n")
            else:
                file_contents.append("Test packet to port " + str(port) + " failed."+"\n")

        ports_list = []
        if open_ports:
            for port in open_ports:
                service_name = get_service_name(port)
                found_port = [port, service_name]
                if isExclusive == "Y" and len(filter_list) > 0:
                    for protocol in filter_list:
                        if found_port[1] == protocol:
                            file_contents.append("Port: " + str(found_port[0]) + ", Service: " + found_port[1] +"\n")
                            ports_list.append(found_port)
                else:
                    file_contents.append("Port: " + str(found_port[0]) + ", Service: " + found_port[1] +"\n")
                    ports_list.append(found_port)
        else:
            print("No open ports found.")

        isPrinted = 0
        if len(filter_list) != 0:
            for port in ports_list:
                for protocol in filter_list:
                    if port[1] == protocol and isPrinted == 0:
                        for row in file_contents:
                            file_output.write(row)
                        file_output.write("----------------------------------------------------------\n")
                        isPrinted = 1
        else:
            for row in file_contents:
                file_output.write(row)
                file_output.write("----------------------------------------------------------\n")

    file_object.close()
    file_output.close()

if __name__ == "__main__":
    main()