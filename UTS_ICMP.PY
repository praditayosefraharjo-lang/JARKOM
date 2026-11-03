from socket import *
import os
import sys
import struct
import time
import select

ICMP_ECHO_REQUEST = 8

ICMP_ERRORS = {
    0: "Destination Network Unreachable",
    1: "Destination Host Unreachable",
    2: "Destination Protocol Unreachable",
    3: "Destination Port Unreachable",
    4: "Fragmentation Required",
    5: "Source Route Failed",
}


def checksum(source):
    # source must be bytes
    csum = 0
    countTo = (len(source) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = source[count + 1] * 256 + source[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(source):
        csum = csum + source[len(source) - 1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(mySocket, ID, seq, timeout, destAddr):
    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # Fill in start
        # Fetch the ICMP header from the IP packet (IP header = first 20 bytes)
        icmpHeader = recPacket[20:28]
        icmpType, code, recvChecksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

        # Echo reply (type 0) that belongs to us
        if icmpType == 0 and packetID == ID:
            ttl = recPacket[8]                                   # TTL is byte 8 of IP header
            timeSent = struct.unpack("d", recPacket[28:28 + 8])[0]
            rtt = (timeReceived - timeSent) * 1000               # ms
            return (rtt, ttl, len(recPacket) - 20, sequence)

        # Destination unreachable (type 3): original request is embedded after the outer ICMP header
        if icmpType == 3:
            innerICMP = recPacket[48:56]                         # 20 IP + 8 ICMP + 20 inner IP
            if len(innerICMP) == 8:
                _, _, _, innerID, _ = struct.unpack("bbHHh", innerICMP)
                if innerID == ID:
                    return ICMP_ERRORS.get(code, "ICMP error, code %d" % code)
        # Fill in end

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."


def sendOnePing(mySocket, destAddr, ID, seq):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, seq)
    data = struct.pack("d", time.time())

    myChecksum = checksum(header + data)
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, seq)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1))


def doOnePing(destAddr, timeout, seq):
    icmp = getprotobyname("icmp")
    mySocket = socket(AF_INET, SOCK_RAW, icmp)
    myID = os.getpid() & 0xFFFF
    sendOnePing(mySocket, destAddr, myID, seq)
    delay = receiveOnePing(mySocket, myID, seq, timeout, destAddr)
    mySocket.close()
    return delay


def ping(host, timeout=1, count=10):
    dest = gethostbyname(host)
    print("Pinging " + dest + " (" + host + ") using Python:")
    print("")

    rtts = []
    sent = 0
    try:
        for seq in range(1, count + 1):
            sent += 1
            result = doOnePing(dest, timeout, seq)
            if isinstance(result, tuple):
                rtt, ttl, size, sequence = result
                rtts.append(rtt)
                print("Reply from %s: bytes=%d seq=%d ttl=%d time=%.2f ms"
                      % (dest, size, sequence, ttl, rtt))
            else:
                print(result)
            time.sleep(1)  # one second between pings
    except KeyboardInterrupt:
        pass

    # Statistics
    print("\n--- %s ping statistics ---" % host)
    received = len(rtts)
    loss = (sent - received) / sent * 100 if sent else 0
    print("%d packets transmitted, %d received, %.1f%% packet loss" % (sent, received, loss))
    if rtts:
        print("rtt min/avg/max = %.2f/%.2f/%.2f ms"
              % (min(rtts), sum(rtts) / len(rtts), max(rtts)))


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    ping(target)