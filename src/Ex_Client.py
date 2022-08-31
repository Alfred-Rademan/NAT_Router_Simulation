import atexit
from concurrent.futures import thread
import ipaddress
from multiprocessing.connection import wait
from pickle import FALSE, TRUE
import threading
from time import sleep
import scapy
import socket
import dhcppython
import time
from threading import Thread, Lock, current_thread


from TCP_send import create_socket, tcp_rec, tcp_send
s = socket.socket()
mac_addr = 'AB:CD:BE:EF:C0:74'
ip = '10.0.0.3'
tcp_host = '127.0.0.1'
tcp_port = 8081
recID = ''

def tcp_sender(s):
    user_input = "start"
    while user_input.strip() != "/e":
        user_input = input("Some input please: ")
        user_ip = input("Some input ip: ")
        tcp_send(s,user_input,ip,user_ip.strip())



def main():
    
    try:
        s.bind(("", tcp_port))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error as e:
        print(str(e))
    s.listen(1)  
    conn,address = s.accept()
    sender = threading.Thread(target = tcp_sender,args= [conn])
    sender.start()
    while True:
        data = tcp_rec(conn)
        data_1 = data[41:].decode("utf-8")
        print(data_1)

def disconnect():
    s.close()
if __name__ == '__main__':
    main()
atexit.register(disconnect)