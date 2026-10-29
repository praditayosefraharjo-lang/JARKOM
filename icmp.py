import socket
import os
import sys
import struct
import time
import select

def resolve_hostname_to_ip(hostname):
    try:
        ip=socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return None

def create_socket():
    try:
        return socket.socket(socket.AF_INET, socket.sock_RAM, socket.IPPROTO_ICMP)
    except PermissionError:
        print("YOU DONT HAVE AMDIN PREMESIONS !!! Run it as admin")
        sys.exit()

def checksum(source_byte):

    sum = 0

    count_to =(len(source_byte)// 2)*2

    for count in range(0, count_to, 2):
        this_val = source_byte[count + 1] * 256 + source_byte[count]
        sum = sum + this_val
        sum = sum & 0xffffffff

    if count_to < len(source_byte):
        sum = sum + source_byte[-1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum +(sum >> 16)


    answer = ~sum & 0xffff
    return answer

def build_packet(id, sequence_number):
    icmp_type = 8
    icmp_code = 0
    checksum_dummy = 0
    payload_data = b"PingPython"

    header = struct.pack("bbHHh",icmp_type,icmp_code,checksum_dummy,id, sequence_number)
    packet = header + payload_data

    calculated_checksum = checksum_dummy(packet)

    header = struct.pack("bbHHh",icmp_type,icmp_code,calculated_checksum,id, sequence_number)

    return header + payload_data

def send_and_receive(icmp_socket, packet, destination_ip, identifier, timeout=1):
    send_time = time.time()
    icmp_socket.sendto(packet, (destination_ip, 1))

    while True:
        ready = select.select([icmp_socket], [], [], timeout)
        if not ready[0]:
            return None   # timeout

        recv_time = time.time()
        recv_packet, addr = icmp_socket.recvfrom(1024)

        icmp_header = recv_packet[20:28]
        _type, code, recv_checksum, recv_id, sequence = struct.unpack("bbHHh", icmp_header)

        if _type == 0 and recv_id == identifier:
            return (recv_time - send_time) * 1000   # RTT dalam ms

if __name__ == "__main__":

    print("Select a target host to ping:")
    print("1. 8.8.8.8 (Google DNS)")
    print("2. 1.1.1.1 (Cloudflare DNS)")
    print("3. www.google.com")

    while True:
        try:
            choice = int(input("Enter your choice (1-3): "))
            if choice in [1, 2, 3]:
                break
            print("Please enter a number between 1 and 3")
        except ValueError:
            print("Please enter a valid number")
    
    target_hosts = {
        1: "8.8.8.8",
        2: "1.1.1.1",
        3: "142.250.70.196"
    }

    target_host = target_hosts[choice]
    ip = resolve_hostname_to_ip(target_host)
    if ip is None:
        print(f"Could not resolve hostname: {target_host}")
        sys.exit(1)

    print(f"pinging {target_host} [{ip}]")

    icmp_socket = create_socket()

    packet_id = os.getpid() & 0xFFFF
    seq_num = 1
    rtts = []
    received = 0

    print(f"Pinging {ip} in Python...")

    for seq_num in range(1, 5):
        packet = build_packet(packet_id, seq_num)
        delay = send_and_receive(icmp_socket, packet, ip, packet_id)
        if delay is None:
            print("Request timed out.")
        else:
            rtts.append(delay)
            received += 1
            print(f"Reply from {ip}: icmp_seq={seq_num} RTT={delay:.2f} ms")

    print(f"\n========== Ping statistics for {ip}: ==========")
    print(f"    Packets: Sent = 4, Received = {received}, Lost = {4 - received},")
    print(f"    Approximate round trip times in milli-seconds:")
    if rtts:  # Only calculate statistics if received packets
        print(f"        Minimum = {min(rtts):.2f}, Maximum = {max(rtts):.2f}, Average = {sum(rtts)/len(rtts):.2f}")
    else:
        print("        No packets received - cannot calculate RTT statistics")
    
    