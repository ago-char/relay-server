#!/bin/python3

import socket
import sys
import time
import threading
import select

REMOTE_SERVER = 1
REMOTE_CLIENT = 2

def connect_to(addr: tuple) -> socket.socket:
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(addr)
        client.setblocking(False)
        print(f"Connected to server at {client.getp}")
        return client
    except Exception as e:
        print(f"Exception: {e.__class__.__name__}, {str(e)}")
        print("oho")
        return None

def is_binded(sock: socket.socket) -> bool:
    try:
        # If the socket is bound, getsockname() will return a valid address tuple
        sock_name = sock.getsockname()
        # If the socket is not bound, it will likely return an empty address or (0, 0) or (0, 0, 0, 0)
        return sock_name != ('0.0.0.0', 0) and sock_name != ('::', 0)
    except Exception:
        # An error/Exception typically means the socket is not bound or another error occurred
        return False
    

def get_bindAddress(sock: socket.socket) -> tuple:
    try:
        if is_binded(sock):
            sock_name = sock.getsockname()
            return sock_name
    except Exception:
        return None


# start listening on specified lhost:lport, defaulting to localhost:9999, if value not given 
def start_listening(lhost = 'localhost', lport = 9999) -> socket.socket:
    # init socket 
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # set socket to be able to reuse address if not listening already (this is useful when connection is already established on host:port and socket is closed, but you want to reopen it for listening)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # bind to get ready for listening 
    try:
        server_sock.bind((lhost, lport))
        server_sock.listen(5)
        server_sock.setblocking(False)
        return server_sock
    except Exception as e:
        print(f"Exception: {e.__class__.__name__}, {str(e)}")
        sys.exit(f"Exited 1. Unable to listen on {lhost}:{lport}...")


# Function to check if the socket is in a listening state
def is_listening(sock: socket.socket) -> bool:
    try:
        # Try to retrieve socket options and check for the state
        sock_type = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        return sock_type == 1  # Returns True if the socket is listening
    except Exception as e:
        return False  # In case of any error or expection, assume it's not listening


def accept_connection(server_sock: socket.socket) -> tuple:
    if is_listening(server_sock):
        print(f"Listening on {get_bindAddress(server_sock)} ...")
        in_sock, in_addr = server_sock.accept()
        in_sock.setblocking(False)
        print(f"Connected to {in_sock.getpeername()}...")
        return (in_sock, in_addr)
    

def is_connected(sock: socket.socket, msg: str) -> bool:
    pass


def send_to(sock: socket.socket, msg: str) -> int:
    try:
        msglen = len(msg)
        total_sent = 0
        peer = sock.getpeername()
        while msg and total_sent < msglen:
            newlen = len(msg)
            # data_sent = sock.send(msg.encode())
            if not isinstance(msg, bytes):
                data_sent = sock.send(msg.encode())
            else:
                data_sent = sock.send(msg)
            total_sent += data_sent
            msg = msg[data_sent:newlen]
        print(f"{total_sent} out of {msglen} bytes sent to {peer}")
        return total_sent
    except Exception as e:
        print(f"Exception: {e.__class__.__name__}, {str(e)}")
        print(f"Send Error, Only {total_sent} sent out of {msglen}.")
        return total_sent


def receive_from(sock: socket.socket) -> str:
    try:
        data = sock.recv(4096)
        # return data if isinstance(data, str) else data.decode()
        return data if isinstance(data, bytes) else data.decode()
    except Exception as e:
        print(f"Exception: {e.__class__.__name__}, {str(e)}")
        print(f"Error Receiving..")

def hexdump(src, length=8):
    src = str(src)
    FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    N=0; result=''
    while src:
       s,src = src[:length],src[length:]
       hexa = ' '.join(["%02X"%ord(x) for x in s])
       s = s.translate(FILTER)
       result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
       N+=length
    print(result)
    return result



def main() -> None:
    lhost = str(sys.argv[1])
    lport = int(sys.argv[2])

    # rhost = str(sys.argv[3])
    # rport = int(sys.argv[4])
    rhost = 'localhost'
    rport = 21

    conn = False

    server_sock = start_listening(lhost, lport)
    sock_list = [server_sock]
    buffer_list = []

    while True:

        try:
            ready_to_read, ready_to_write, in_error = select.select(sock_list, sock_list, [], 5)
        except Exception as e:
            print(f"Exception: {e.__class__.__name__}, {str(e)}")
            print("Some Error on socket...select")
            break

        if server_sock in ready_to_read:
            in_sock, _ = accept_connection(server_sock)
            sock_list.append(in_sock)
            if buffer_list:
                for data in buffer_list:
                    send_to(in_sock, data)
                buffer_list.clear()
            
            if not conn:
                client_sock = connect_to((rhost, rport))
                sock_list.append(client_sock)
                conn = True
            continue


        readable_sock: socket.socket
        for readable_sock in ready_to_read:
            broadcast = False
            if not readable_sock is server_sock:
                peer = readable_sock.getpeername()
                data = receive_from(readable_sock)
                if readable_sock is client_sock:
                    broadcast = True
                if data:
                    print(f"{len(data)} bytes received from {peer}.")
                    hexdump(data)
                    if not broadcast: # if broadcast is not set only send to the other end (main server)
                        if client_sock in ready_to_write:
                            send_to(client_sock, data)
                    else:
                        for writable_sock in ready_to_write:
                            if not writable_sock is client_sock and not writable_sock is server_sock:
                                send_to(writable_sock, data)
                                buffer_list.clear()
                            else:
                                buffer_list.append(data)
                else:
                    buffer_list.clear()
                    conn = False
                    if not writable_sock is client_sock and not writable_sock is server_sock:
                        readable_sock.shutdown(socket.SHUT_RDWR)
                    readable_sock.close()
                    sock_list.remove(readable_sock)
                    print("Connection closed...\n")



if __name__ == "__main__":
    main()