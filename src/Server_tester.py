import select, socket
HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 4432  # The port used by the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("", PORT))
    s.listen()
    conn, addr = s.accept()
    data = conn.recv(100)
    
    print(data.decode("utf-8"))