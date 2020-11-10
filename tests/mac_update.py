import socket
import sys
import os
import time

def send_lb_data(data):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect("/var/lib/testpmd/lb.sock")
    except socket.error as msg:
        print(msg)
        sys.exit(1)
    try:
        print("sending %s" % data);
        sock.sendall(data)
    finally:
        sock.close();

# Add
message = b'1,20:30:40:50:60:91;'
send_lb_data(message)
message = b'1,20:30:40:50:60:92;'
send_lb_data(message)
message = b'1,20:30:40:50:60:93;'
send_lb_data(message)
message = b'1,20:30:40:50:60:94;'
send_lb_data(message)

time.sleep(15)

# Remove
message = b'2,20:30:40:50:60:92;'
send_lb_data(message)

