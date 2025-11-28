import socket

HOST = "127.0.0.1"
PORT = 80

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(5)

print(f"Dummy server listening on {HOST}:{PORT}")

while True:
    conn, addr = s.accept()
    conn.recv(1024)        # odbieramy cokolwiek
     # zamykamy — minimalny flow
