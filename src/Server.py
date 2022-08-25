import ipaddress
import scapy
import socket
import dhcppython
import threading

mac_addr = 'BB:CD:BE:EF:C0:34'
ip_pool = []
ip_assigned = []
assigned_table = {}

def ip_create(start, end):
    for num in range(start,end):
        ip_pool.append('10.0.0.' + str(num))

def recieve_DHCPConnect(server:socket):

    while True:

        recv_packet, addr = server.recvfrom(1024)
        packet = dhcppython.packet.DHCPPacket.from_bytes(recv_packet)
        dhcp_type = packet.options.as_dict()['dhcp_message_type']
        print(packet)
        print(dhcp_type)

        if packet.op == 'BOOTREQUEST' and dhcp_type == 'DHCPDISCOVER':
            handle_Connect(packet,server)

def connect(server):
    recv_packet, addr = server.recvfrom(1024)
    packet = dhcppython.packet.DHCPPacket.from_bytes(recv_packet)
    dhcp_type = packet.options.as_dict()['dhcp_message_type']
    if packet.op == 'BOOTREQUEST' and dhcp_type == 'DHCPREQUEST':
        print(packet.yiaddr)

def handle_Connect(packet, server):

    client_mac = packet.chaddr
    rec_ID = packet.xid
    offered_IP = None
    i = 2

    while offered_IP == None and ip_assigned.count != ip_pool.count :
        test_IP = ip_pool[i]
        if test_IP not in ip_assigned:
            offered_IP = test_IP
            ip_assigned.append(test_IP)
        i += 1
    
    offer_packet = dhcppython.packet.DHCPPacket.Offer(mac_addr,0,rec_ID,
    ipaddress.IPv4Address(offered_IP))
    server.sendto(offer_packet.asbytes,('<broadcast>', 4020))
    connect(server)    
    

def main():

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.bind(("", 5000))

    ip_create(1,11)
    ip_assigned.append('10.0.0.1')

    recieve_thread = threading.Thread(target=recieve_DHCPConnect,args= (server,))
    recieve_thread.start()

if __name__ == '__main__':
    main()
