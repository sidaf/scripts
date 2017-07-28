import socket;

for port in range(1,65535):
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result=sock.connect_ex(('217.146.111.122',port))
    if result == 0:
        print('%s open' % port)
