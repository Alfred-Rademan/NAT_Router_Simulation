import scapy
import socket
import dhcppython

mac_addr = 'AB:CD:BE:EF:C0:74'

def send_DHCPConnect(clientsock:socket):
    dhcp_packet = dhcppython.packet.DHCPPacket.Discover(mac_addr)
    clientsock.sendto(dhcp_packet.asbytes,('<broadcast>',5000))


def main():
    clientsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    clientsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    clientsock.bind(('',4020))
    send_DHCPConnect(clientsock)

if __name__ == '__main__':
    main()

