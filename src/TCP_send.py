
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

def tcp_rec(rec_socket):
        chunk = rec_socket.recv(1024)
        return chunk

def create_socket(HOST,PORT):
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        print("worked")
        return s
