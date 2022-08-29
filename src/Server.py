import atexit
from concurrent.futures import thread
from dataclasses import dataclass
import ipaddress
from itertools import count
import queue
import json
from re import T
from time import sleep
import time
from traceback import print_list
from TCP_send import create_socket, tcp_rec, tcp_send, tcp_switch_send
import scapy
import socket
import dhcppython
from threading import Thread, Lock
import threading
from collections import deque


mac_addr = 'BB:CD:BE:EF:C0:34'
ip_pool = []
ip_assigned = []
assigned_table = {}
nat_table = {}
ex_nat_table = {}
ex_queue_table = {}
queue_messages = []
lock = Lock()
leaseTime = 300
count_t = 0

ip_natbox = "127.0.0.1"
def disconnect(packet, addr):
    client_mac = packet.chaddr
    client_ip = packet.yiaddr
    ip_assigned.remove(str(client_ip))
    assigned_table.pop(client_mac)
    nat_table.pop(addr)
    print(nat_table)
    print("disc")

ip_socket_table = {}
tcp_server = socket.socket()

def ip_create(start, end):
    for num in range(start,end):
        ip_pool.append('10.0.0.' + str(num))

def recieve_DHCPConnect(server:socket):
    while True:
        reconnect = False
        recv_packet, addr = server.recvfrom(1024)
        try :
           icmp_packet = json.loads(recv_packet.decode('utf-8'))
           icmp_handler(server,icmp_packet)
        except:
            print("no")
            packet = dhcppython.packet.DHCPPacket.from_bytes(recv_packet)   
            dhcp_type = packet.options.as_dict()['dhcp_message_type']
            if dhcp_type == "DHCPRELEASE" :
                disconnect(packet,addr)

             # elif addr in nat_table:

                #  reconnect = True
                 # print("renew")
                 # connect(server, reconnect, packet)

            elif packet.op == 'BOOTREQUEST' and dhcp_type == 'DHCPDISCOVER':
                handle_Connect(packet,server)

                    

def icmp_handler(server, icmp_package):
    print(nat_table)
    addr = list(nat_table.keys())[list(nat_table.values()).index(ipaddress.IPv4Address(icmp_package['send_IP']))]
    print(addr)
    icmp_tosend = str.encode(json.dumps(icmp_package))
    #server.sendto(icmp_tosend, )


    


            

def connect(server, reconnect, pre_pack):
    print(reconnect)

    if (not reconnect) :
        global count_t
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
            client_list_thread = threading.Thread(target=client_listener,args=[count_t])
            client_list_thread.start()
            count_t = count_t+1
            


        


    else:
        connect_packet = dhcppython.packet.DHCPPacket.Ack(mac_addr,leaseTime,pre_pack.xid,pre_pack.yiaddr)
        server.sendto(connect_packet.asbytes,('<broadcast>',4020))
        client_list_thread = threading.Thread(target=client_listener,args=("1"))
        client_list_thread.start()

def handle_Connect(packet, server):
    client_mac = packet.chaddr
    rec_ID = packet.xid
    bruh = True
    if (client_mac in assigned_table and bruh != True):

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

def client_sender(con,name):
    while True:
        
        if(len(queue_messages[name])>0):
            
            lock.acquire()
            data = queue_messages[name].pop()
            tcp_switch_send(con,data)
            lock.release()

        
def client_listener(name):
    conn,addr = client_creator()
    sender_thread = threading.Thread(target=client_sender,args=[conn,name])
    sender_thread.start()
    mac = ""
    con_port = 767 
    print("Connected to %s", addr)
    while True:
        data = tcp_rec(conn)
        print("ahhh")
        if data != None:
            print(data[:17].decode('utf-8'))
            start_ip = data[17:26].decode('utf-8')
            print(start_ip)
            port_sender = int.from_bytes(data[27:29],"big")
            print(port_sender)
            end_ip = data[29:38].decode('utf-8')
            print(end_ip)
            port_rec = int.from_bytes(data[39:42],"big")
            print(port_rec)
            
            if(end_ip == '10.0.0.4'):
                print("here")
                lock.acquire()
                que = queue_messages[1]
                que.append(data)
                print(len(que))
                lock.release()
            elif( (start_ip+str(port_sender)) in ex_nat_table ):
                data2 = bytes(mac_addr,"utf-8") + bytes(ip_natbox,"utf-8")+data[27:29]+data[29:]
                ex_queue_table[start_ip+str(port_sender)].append(data2)
                print("exists")
            else:
                ex_nat_table[start_ip+str(port_sender)] = end_ip+str(port_rec)
                if( (start_ip+str(port_sender)) in ex_nat_table ):
                        print("truuuue")
                ex_queue_table[start_ip+str(port_sender)] = deque()
                external_sock(end_ip,port_rec,start_ip,port_sender)
                data2 = bytes(mac_addr,"utf-8") + bytes(ip_natbox,"utf-8")+data[27:29]+data[29:38]+data[39:42]+data[42:]
                ex_queue_table[start_ip+str(port_sender)].append(data2)
                print("bruh")
                
            print(str(data))
        if str(data.strip()) == 'b\'\'' :
            break
    atexit.register(close_con,conn)

def external_sock(end_ip,port_rec,start_ip,port_sender):
    sock = socket.socket()
    sock = create_socket(end_ip,port_rec)
    sender_thread =  threading.Thread(target = ex_sender,args = [start_ip,port_sender,sock] )
    sender_thread.start()
    
def ex_rec(conn,end,port_rec):
    while True:
        data = tcp_rec(conn)
    
    
def ex_sender(start_ip, port_sender,sock):
    while True:
        if len(ex_queue_table[start_ip+str(port_sender)])>0:
            data = ex_queue_table[start_ip+str(port_sender)].pop()
            print(data)
            tcp_switch_send(sock,data)

def ex_send(sock):
    while True:
        sock.send()


def close_con(s):
    s.close()
    thread.join()
def close():
    tcp_server.close()



def client_creator():
    lock.acquire()
    conn, addr = tcp_server.accept()
    queue_temp =deque()
    queue_messages.append(queue_temp)
    lock.release()


    return conn,addr


def main():
    tcp_host = '127.0.0.1'
    tcp_port = 1666
    tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        tcp_server.bind(("", tcp_port))
    except socket.error as e:
        print(str(e))
    tcp_server.listen(200)  
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    pp = socket.gethostname()
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