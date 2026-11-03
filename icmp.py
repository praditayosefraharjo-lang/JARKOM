import socket
import os
import sys
import struct
import time
import select


def resolve_hostname_to_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def create_socket():
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Permission denied! Jalankan dengan sudo: sudo python3 icmp.py")
        sys.exit(1)


def checksum(source_bytes):
    total = 0
    count_to = (len(source_bytes) // 2) * 2

    # jumlahkan per 16 bit (big-endian / network byte order)
    for count in range(0, count_to, 2):
        total += (source_bytes[count] << 8) + source_bytes[count + 1]

    # kalau jumlah byte ganjil, byte terakhir jadi high byte
    if count_to < len(source_bytes):
        total += source_bytes[-1] << 8

    # lipat carry ke 16 bit
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16

    return ~total & 0xFFFF


def build_packet(identifier, sequence_number):
    icmp_type = 8   # Echo Request
    icmp_code = 0
    payload_data = b"PingPython"

    # header dengan checksum = 0 dulu
    header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, identifier, sequence_number)
    calculated_checksum = checksum(header + payload_data)

    # susun ulang header dengan checksum yang benar
    header = struct.pack("!BBHHH", icmp_type, icmp_code, calculated_checksum,
                         identifier, sequence_number)
    return header + payload_data


def send_and_receive(icmp_socket, packet, destination_ip, identifier, sequence_number, timeout=1):
    send_time = time.time()
    icmp_socket.sendto(packet, (destination_ip, 0))
    deadline = send_time + timeout

    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None  # timeout

        ready = select.select([icmp_socket], [], [], remaining)
        if not ready[0]:
            return None  # timeout

        recv_packet, addr = icmp_socket.recvfrom(1024)
        recv_time = time.time()

        # panjang header IP dari field IHL (4 bit bawah byte pertama, satuan 4 byte)
        ip_header_len = (recv_packet[0] & 0x0F) * 4
        icmp_header = recv_packet[ip_header_len:ip_header_len + 8]
        if len(icmp_header) < 8:
            continue

        _type, code, recv_checksum, recv_id, recv_seq = struct.unpack("!BBHHH", icmp_header)

        if _type == 0 and recv_id == identifier and recv_seq == sequence_number:
            return (recv_time - send_time) * 1000  # RTT dalam ms


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
        3: "www.google.com",
    }

    target_host = target_hosts[choice]
    ip = resolve_hostname_to_ip(target_host)
    if ip is None:
        print(f"Could not resolve hostname: {target_host}")
        sys.exit(1)

    icmp_socket = create_socket()

    packet_id = os.getpid() & 0xFFFF
    rtts = []
    received = 0

    print(f"Pinging {target_host} [{ip}] with Python...")

    try:
        for seq_num in range(1, 5):
            packet = build_packet(packet_id, seq_num)
            delay = send_and_receive(icmp_socket, packet, ip, packet_id, seq_num)
            if delay is None:
                print("Request timed out.")
            else:
                rtts.append(delay)
                received += 1
                print(f"Reply from {ip}: icmp_seq={seq_num} RTT={delay:.2f} ms")
            time.sleep(1)
    finally:
        icmp_socket.close()

    print(f"\n========== Ping statistics for {ip}: ==========")
    print(f"    Packets: Sent = 4, Received = {received}, Lost = {4 - received},")
    print(f"    Approximate round trip times in milli-seconds:")
    if rtts:
        print(f"        Minimum = {min(rtts):.2f}, Maximum = {max(rtts):.2f}, "
              f"Average = {sum(rtts)/len(rtts):.2f}")
    else:
        print("        No packets received - cannot calculate RTT statistics")