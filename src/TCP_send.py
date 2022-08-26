
def tcp_send(sender_socket,data):
        sender_socket.send(data)


def tcp_rec(rec_socket):
        chunk = rec_socket.rec(1024)




import socket
HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((HOST, PORT))
tcp_send(s,"hello")
