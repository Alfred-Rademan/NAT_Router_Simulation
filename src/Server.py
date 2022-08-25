import scapy
import socket
import dhcppython

def recieve_DHCPConnect(server:socket):  
    recv_packet = server.recv(1024)
    packet = dhcppython.packet.DHCPPacket.from_bytes(recv_packet)
    print(packet)


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.bind(("", 5000))
    recieve_DHCPConnect(server)

if __name__ == '__main__':
    main()
