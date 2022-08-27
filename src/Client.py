import ipaddress
import scapy
import socket
import dhcppython
import time
from threading import Thread, Lock
mac_addr = 'AB:CD:BE:EF:C0:74'
ip = ''
recID = ''
connected = False

def timeout(lease_time, clientsock):
    while True:
        print("thread started")
        time.sleep(lease_time)
        print("slept")
        print(ip)
        send_Req(ip,recID,clientsock)
        print("renewed")


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

        if offer_ip != ipaddress.IPv4Address(0) and offer_ip != ipaddress.IPv4Address(1):
            send_Req(offer_ip, rec_ID, clientsock)

        elif offer_ip == ipaddress.IPv4Address(0):
            print('DHCP server has too many devices')

        else:
            print('Device already assigned local IP')

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
    print('reached')
    connect(clientsock)

# Add if condition
def connect(clientsock):
    print("c0nnect")
    recv_packet, addr = clientsock.recvfrom(1024)
    print("c0nnect2")
    packet = dhcppython.packet.DHCPPacket.from_bytes(recv_packet)
    global ip
    global recID
    global connected
    ip = packet.yiaddr 
    recID = packet.xid
    time = packet.secs
    print(time)
    if not connected:
        time_Thread = Thread(target=timeout, args=(time, clientsock))
        time_Thread.start()
    connected = True
    print(ip)



def main():
    clientsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    clientsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    clientsock.bind(('',4020))
    send_DHCPDisc(clientsock)

if __name__ == '__main__':
    main()

