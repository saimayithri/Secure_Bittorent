import socket, json

def test_tracker():
    s = socket.socket()
    s.connect(('localhost', 5000))
    s.sendall(json.dumps({"type":"list_files"}).encode())
    print("Response:", s.recv(1024).decode())
    s.close()

test_tracker()