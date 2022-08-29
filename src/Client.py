import atexit
from concurrent.futures import thread
import ipaddress
from multiprocessing.connection import wait
from pickle import FALSE, TRUE
from random import random
import threading
from time import sleep
import json
import scapy
import socket
import dhcppython
import time
import random
from threading import Thread, Lock, current_thread
from Ip_simulator import gen_ip, gen_mac


from TCP_send import create_socket, tcp_rec, tcp_send, tcp_send_try

mac_addr = 'AB:CD:BE:EF:C0:74'
ip = '10.0.0.3'
server_ip = ''
tcp_host = '127.0.0.1'
tcp_port = 1666
tcp_sender_port = 8081
recID = ''
connected = False
timeout_thread = None
lock = Lock()
disc = False
cust_IP = "234.23.34.0"

def timeout(lease_time, clientsock):
    global timeout_thread
    timeout_thread = current_thread()

    while getattr(timeout_thread,"running",True):
        
        print("thread started")
        time.sleep(lease_time)
        print("slept")
        print(ip)
        lock.acquire()
        send_Req(ip,recID,clientsock)
        lock.release()
        

def send_DHCPDisc(clientsock):

    dhcp_packet = dhcppython.packet.DHCPPacket.Discover(mac_addr)
    clientsock.sendto(dhcp_packet.asbytes,('<broadcast>',5000))
    offer_wait(clientsock)

def offer_wait(clientsock):

    recv_packet, addr = clientsock.recvfrom(1024)
    packet = dhcppython.packet.DHCPPacket.from_bytes(recv_packet)
    dhcp_type = packet.options.as_dict()['dhcp_message_type']
    print("here77")
    if packet.op == 'BOOTREPLY' and dhcp_type == 'DHCPOFFER' :

        offer_ip = packet.yiaddr
        ip = offer_ip
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
    ciaddr=ipaddress.IPv4Address(cust_IP),
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
    if not disc:
        recv_packet, addr = clientsock.recvfrom(1024)
        icmp_send(clientsock,"10.0.0.3",addr[1],True)
        print("c0nnect2")
        packet = dhcppython.packet.DHCPPacket.from_bytes(recv_packet)
        global ip
        global server_ip
        global recID
        global connected
        server_ip = packet.yiaddr
        print(server_ip)
        #ip = packet.yiaddr 
        recID = packet.xid
        time = packet.secs
        print(time)

        if not connected:
            icmp_listener = Thread(target=icmp_recieve, args=(clientsock,))
            icmp_listener.start()
            time_Thread = Thread(target=timeout, args=(time, clientsock))
            time_Thread.start()

        connected = True
        print(ip)

def tcp_sender(s):
    user_input = "start"
    global mac_addr
    while user_input.strip() != "/e":
        user_input = input("Some input please: ")
        user_ip = input("Some input ip: ")
        tcp_send_try(s,user_input,ip,user_ip.strip(),mac_addr,tcp_port,tcp_sender_port)
        

def Disconnect(clientsock):
    global disc
    disc = True
    global ip
    packet = dhcppython.packet.DHCPPacket(op="BOOTREQUEST",
    htype="ETHERNET",
    hlen=6,
    hops=0,
    xid=recID,
    secs=0,
    flags=0,
    ciaddr=ipaddress.IPv4Address(0),
    yiaddr=ipaddress.IPv4Address(ip),
    siaddr=ipaddress.IPv4Address(0),
    giaddr=ipaddress.IPv4Address(0),
    chaddr=mac_addr,
    sname=b'',
    file=b'',
    options=dhcppython.options.OptionList([dhcppython.options.options.short_value_to_object(53,"DHCPRELEASE")]))
    clientsock.sendto(packet.asbytes, ('<broadcast>', 5000)) 
    timeout_thread.running = False
    print("Disconnected")

def icmp_send(clientsock,sendTo, addr, first_send):
    time_stamp = time.time()
    id = random.getrandbits(5)

    icmp_packet = {
        "ip" : str(ip),
        "send_IP" : str(sendTo),
        "time_stamp" : time_stamp,
        "id" : id,
        "first_send": first_send
    }

    icmp_toSend = str.encode(json.dumps(icmp_packet))
    clientsock.sendto(icmp_toSend,('<broadcast>', addr))

def icmp_recieve(clientsock):
    icmp_thread = current_thread()
    global ip
    while getattr(icmp_thread,"running",True):
        try:
            icmp_packet, addr = clientsock.recvfrom(1024)
            icmp_dict = json.loads(icmp_packet.decode('utf-8'))
            print(icmp_dict)
            if (icmp_dict['first_send'] == True):
                #icmp_dict['first_send'] = False
                icmp_dict["send_IP"] = icmp_dict['ip']
                #icmp_dict['ip'] = ip
                icmp_send(clientsock,icmp_dict['send_IP'],addr[1],False)
            else:
                print("Its back")
        except:
            print("DHCP")

def main():
    clientsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    clientsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    clientsock.bind(('',4020))
    send_DHCPDisc(clientsock)
    lock.acquire()
    #Disconnect(clientsock)
    lock.release()
    global cust_IP
    global mac_addr 
    mac_addr = gen_mac()
    cust_IP = gen_ip()
    
    connected = FALSE
    i = 0
    s = socket.socket()
    while connected != TRUE:
        try:
            s = create_socket("",tcp_port)
            connected = TRUE

        except socket.error as e:
            print(str(e))
            
    sender = threading.Thread(target = tcp_sender,args= [s])
    sender.start()
    print("here")
    while True:
        data = tcp_rec(s)
        data_1 = data[16:].decode("utf-8")
        
        print(data_1)

    

if __name__ == '__main__':
    main()

atexit.register(Disconnect)