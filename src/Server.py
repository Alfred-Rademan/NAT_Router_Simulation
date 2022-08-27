import ipaddress
from traceback import print_list
import scapy
import socket
import dhcppython
from threading import Thread, Lock

mac_addr = 'BB:CD:BE:EF:C0:34'
ip_pool = []
ip_assigned = []
assigned_table = {}
nat_table = {}
lock = Lock()
leaseTime = 3

def ip_create(start, end):
    for num in range(start,end):
        ip_pool.append('10.0.0.' + str(num))

def recieve_DHCPConnect(server:socket):

    while True:
        reconnect = False
        recv_packet, addr = server.recvfrom(1024)
        packet = dhcppython.packet.DHCPPacket.from_bytes(recv_packet)
        dhcp_type = packet.options.as_dict()['dhcp_message_type']
        if addr in nat_table:
            reconnect = True
            print("renew")
            connect(server, reconnect, packet)
        if packet.op == 'BOOTREQUEST' and dhcp_type == 'DHCPDISCOVER':
            handle_Connect(packet,server)
        
            

def connect(server, reconnect, pre_pack):

    if (not reconnect) :

        print('reached connect')
        recv_packet, addr = server.recvfrom(1024)
        print("rec Pack")
        packet = dhcppython.packet.DHCPPacket.from_bytes(recv_packet)
        dhcp_type = packet.options.as_dict()['dhcp_message_type']
        print(reconnect)
        if (packet.op == 'BOOTREQUEST' and dhcp_type == 'DHCPREQUEST'):
            client_mac = packet.chaddr
            assigned_table[client_mac] = packet.yiaddr
            nat_table[addr] = packet.yiaddr
            connect_packet = dhcppython.packet.DHCPPacket.Ack(mac_addr,leaseTime,packet.xid,packet.yiaddr)
            server.sendto(connect_packet.asbytes,('<broadcast>',4020))
    else:
        connect_packet = dhcppython.packet.DHCPPacket.Ack(mac_addr,leaseTime,pre_pack.xid,pre_pack.yiaddr)
        server.sendto(connect_packet.asbytes,('<broadcast>',4020))

def handle_Connect(packet, server):

    client_mac = packet.chaddr
    rec_ID = packet.xid

    if (client_mac in assigned_table):

        print("Client already assigned an IP")
        offer_packet = dhcppython.packet.DHCPPacket.Offer(mac_addr,0,rec_ID,
        ipaddress.IPv4Address(1))
        server.sendto(offer_packet.asbytes,('<broadcast>', 4020))

    else:

        offered_IP = None
        i = 2

        while offered_IP == None and ip_assigned.count != ip_pool.count and i < 10:

            test_IP = ip_pool[i]

            if test_IP not in ip_assigned:

                offered_IP = test_IP
                ip_assigned.append(test_IP)

            i += 1

        if offered_IP == None :

            offer_packet = dhcppython.packet.DHCPPacket.Offer(mac_addr,0,rec_ID,
            ipaddress.IPv4Address(0))
            server.sendto(offer_packet.asbytes,('<broadcast>', 4020))

        else:

            offer_packet = dhcppython.packet.DHCPPacket.Offer(mac_addr,0,rec_ID,
            ipaddress.IPv4Address(offered_IP))
            server.sendto(offer_packet.asbytes,('<broadcast>', 4020))
            connect(server,False,offer_packet)    
    

def main():

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    pp = socket.gethostname()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.bind(("", 5000))

    ip_create(1,11)
    ip_assigned.append('10.0.0.1')

    recieve_thread = Thread(target=recieve_DHCPConnect,args= (server,))

    recieve_thread.start()

if __name__ == '__main__':
    main()
