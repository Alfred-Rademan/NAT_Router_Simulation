import atexit
from concurrent.futures import thread
from dataclasses import dataclass
import ipaddress
from re import T
from time import sleep
from traceback import print_list
from TCP_send import tcp_rec, tcp_send
import scapy
import socket
import dhcppython
import threading
from socket import SHUT_RDWR

mac_addr = 'BB:CD:BE:EF:C0:34'
ip_pool = []
ip_assigned = []
assigned_table = {}
nat_table = {}
ip_socket_table = {}
tcp_server = socket.socket()

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
        client_mac = packet.chaddr
        assigned_table[client_mac] = packet.yiaddr
        nat_table[addr] = packet.yiaddr
        print(nat_table)
        connect_packet = dhcppython.packet.DHCPPacket.Ack(mac_addr,0,packet.xid,packet.yiaddr)
        server.sendto(connect_packet.asbytes,('<broadcast>',4020))
        print("here")
        client_list_thread = threading.Thread(target=client_listener,args=("1"))
        client_list_thread.start()
        



def handle_Connect(packet, server):
    client_mac = packet.chaddr
    rec_ID = packet.xid
    offered_IP = None
    i = 2

    while offered_IP == None and ip_assigned.count != ip_pool.count and i < 10:
        test_IP = ip_pool[i]
        if test_IP not in ip_assigned:
            offered_IP = test_IP
            ip_assigned.append(test_IP)
        i += 1
    #print(str(ipaddress.IPv4Address(0)))
    if offered_IP == None :
        offer_packet = dhcppython.packet.DHCPPacket.Offer(mac_addr,0,rec_ID,
        ipaddress.IPv4Address(0))
        server.sendto(offer_packet.asbytes,('<broadcast>', 4020))

    else:

        offer_packet = dhcppython.packet.DHCPPacket.Offer(mac_addr,0,rec_ID,
        ipaddress.IPv4Address(offered_IP))
        server.sendto(offer_packet.asbytes,('<broadcast>', 4020))
        connect(server)
        
        
        
def client_listener(name):
    conn,addr = client_creator()
    print("Connected to %s", addr)
    while True:
        data = tcp_rec(conn)
        if data != None:
            print(data[:8].decode('utf-8'))
            print(data[8:16].decode('utf-8'))
            print(str(data))
        if str(data.strip()) == 'b\'\'' :
            break
    atexit.register(close_con,conn)

def close_con(s):
    s.close()
    thread.join()
def close():
    tcp_server.shutdown(SHUT_RDWR)
    tcp_server.close()
def client_creator():
    conn, addr = tcp_server.accept()
    return conn,addr

def main():
    tcp_host = '127.0.0.1'
    tcp_port = 1666
    tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        tcp_server.bind(("", tcp_port))
    except socket.error as e:
        print(str(e))
    tcp_server.listen()  
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
atexit.register(close)