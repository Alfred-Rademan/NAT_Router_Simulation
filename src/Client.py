from concurrent.futures import thread
import ipaddress
from multiprocessing.connection import wait
from pickle import FALSE, TRUE
import threading
from time import sleep
import scapy
import socket
import dhcppython

from TCP_send import create_socket, tcp_rec, tcp_send

mac_addr = 'AB:CD:BE:EF:C0:74'
ip = '10.0.0.3'
tcp_host = '127.0.0.1'
tcp_port = 1666
def send_DHCPDisc(clientsock):

    dhcp_packet = dhcppython.packet.DHCPPacket.Discover(mac_addr)
    clientsock.sendto(dhcp_packet.asbytes,('<broadcast>',5000))
    offer_wait(clientsock)

def offer_wait(clientsock):

    recv_packet, addr = clientsock.recvfrom(1024)
    packet = dhcppython.packet.DHCPPacket.from_bytes(recv_packet)
    dhcp_type = packet.options.as_dict()['dhcp_message_type']

    if packet.op == 'BOOTREPLY' and dhcp_type == 'DHCPOFFER' :
        offer_ip = packet.yiaddr
        rec_ID = packet.xid
        if offer_ip != ipaddress.IPv4Address(0):
            send_Req(offer_ip, rec_ID, clientsock)

def send_Req(offer_ip, rec_ID,clientsock):

    packet = dhcppython.packet.DHCPPacket(op="BOOTREQUEST",
    htype="ETHERNET",
    hlen=6,
    hops=0,
    xid=rec_ID,
    secs=0,
    flags=0,
    ciaddr=ipaddress.IPv4Address(0),
    yiaddr=ipaddress.IPv4Address(offer_ip),
    siaddr=ipaddress.IPv4Address(0),
    giaddr=ipaddress.IPv4Address(0),
    chaddr=mac_addr,
    sname=b'',
    file=b'',
    options=dhcppython.options.OptionList([dhcppython.options.options.short_value_to_object(53, "DHCPREQUEST")]))
    clientsock.sendto(packet.asbytes, ('<broadcast>', 5000))
    connect(clientsock)

# Add if condition
def connect(clientsock):
    recv_packet, addr = clientsock.recvfrom(1024)
    packet = dhcppython.packet.DHCPPacket.from_bytes(recv_packet)
    ip = packet.yiaddr
    print(ip)

def tcp_sender(s):
    user_input = "start"
    while user_input.strip() != "/e":
        user_input = input("Some input please: ")
        user_ip = input("Some input ip: ")
        tcp_send(s,user_input,ip,user_ip.strip())

def main():
    clientsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    clientsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    clientsock.bind(('',4020))
    send_DHCPDisc(clientsock)
    connected = FALSE
    i = 0
    s = socket.socket()
    while connected != TRUE:
        try:
            s = create_socket("",tcp_port)
            connected = TRUE

        except:
            i = i +1
            print("An exception occurred %s" , i)
    sender = threading.Thread(target = tcp_sender(s),args= (s))
    sender.start()
    while True:
        data = tcp_rec()
        print(data)

    

if __name__ == '__main__':
    main()

