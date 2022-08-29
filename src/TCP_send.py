
import socket
from tokenize import String
def tcp_send(sender_socket,data):
        d = data.encode()
        sender_socket.send(d)
        return d

def tcp_send(sender_socket,data,ip_sender,ip_rec:String):
        ip_1 = bytes(str(ip_sender), 'utf-8')
        ip_2 = bytes(str(ip_rec),'utf-8')
        print(ip_sender)
        d = ip_1+ip_2+data.encode()
        sender_socket.send(d)
        return d

def tcp_send_try(sender_socket, data, ip_sender, ip_rec:String, mac_address, ip_host_port, ip_rec_port):
        ip_1 = bytes(str(ip_sender), 'utf-8')
        ip_2 = bytes(str(ip_rec),'utf-8')
        mac = bytes(str(mac_address),'utf-8')
        send_port = ip_host_port.to_bytes(4, 'big')
        rec_port = ip_rec_port.to_bytes(4, 'big')
        d = mac+ip_1+send_port+ip_2+rec_port+data.encode()
        sender_socket.send(d)
        return d

def tcp_switch_send(sender_socket,data):
        sender_socket.send(data)

def tcp_rec(rec_socket):
        chunk = rec_socket.recv(1024)
        return chunk


def create_socket(HOST,PORT):
        #HOST = "25.70.125.232"
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM, socket.IPPROTO_TCP)
        s.connect((HOST, PORT))
        return s
