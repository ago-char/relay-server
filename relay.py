#!/bin/python3

import socket
import sys
import select

def usuage(scriptName: str):
    msg =f"""
    This script is designed to be relay server (middle proxy) that will listen on spefic port and
    forwad connection back and forth from remote client and remote server using sockets.

    Usuage: {scriptName} <listen_host> <listen_port> <remote_server> <remote_port>

    This script requires 'sudo' or 'admin' privileges if provided privileged ports to work on. 
    """
    print(msg)


def connect_to(addr: tuple) -> socket.socket:
    """
    connect the socket into specified addr i.e (ip, port)
    return connected client socket on success, None on failure
    """
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(addr)
        client.setblocking(False)
        print(f"Connected to server at {client.getpeername()}")
        return client
    except Exception as e:
        print(f"Exception: {e.__class__.__name__}, {str(e)}")
        return None

def is_binded(sock: socket.socket) -> bool:
    """
    check if the given socket is binded
    return true or false
    """
    try:
        # If the socket is bound, getsockname() will return a valid address tuple
        sock_name = sock.getsockname()
        # If the socket is not bound, it will likely return an empty address or (0, 0) or (0, 0, 0, 0)
        return sock_name != ('0.0.0.0', 0) and sock_name != ('::', 0)
    except Exception:
        # An error/Exception typically means the socket is not bound or another error occurred
        return False
    

def get_bindAddress(sock: socket.socket) -> tuple:
    """
    Retrive the bind address and return it
    return None if expection encountered
    """
    try:
        if is_binded(sock):
            sock_name = sock.getsockname()
            return sock_name
    except Exception:
        return None


def start_listening(lhost = 'localhost', lport = 9999) -> socket.socket:
    """
    start listening on specified lhost:lport, defaulting to localhost:9999, if value not given 
    return the listening socket, None if expection encountered
    """
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
        return None


def is_listening(sock: socket.socket) -> bool:
    """
    check if the socket is in a listening state
    returns true or false
    """
    try:
        # Try to retrieve socket options and check for the state
        sock_type = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        return sock_type == 1  # Returns True if the socket is listening
    except Exception as e:
        return False  # In case of any error or expection, assume it's not listening


def accept_connection(server_sock: socket.socket) -> tuple:
    """
    Accept the connection on the socket which is binded and listening on some addr
    """
    if is_listening(server_sock):
        print(f"Listening on {get_bindAddress(server_sock)} ...")
        in_sock, in_addr = server_sock.accept()
        in_sock.setblocking(False)
        print(f"Connected to {in_sock.getpeername()}...")
        return (in_sock, in_addr)


def send_to(sock: socket.socket, msg: str) -> int:
    """
    send given message to specified connected sock
    returns total bytes sent or None when exception encountered
    """
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
        return None


def receive_from(sock: socket.socket) -> str:
    """
    receive data from specified sock and return it
    """
    try:
        data = sock.recv(4096)
        return data if isinstance(data, bytes) else data.decode()
    except Exception as e:
        print(f"Exception: {e.__class__.__name__}, {str(e)}")
        print(f"Error Receiving..")
        return data if isinstance(data, bytes) else data.decode()


def hexdump(src, length=8):
    """
    Function to dump src into hex taken from internet
    """
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

def wrap_up_when_remote_closed_conn(sock_list: list, proxy_server: socket.socket, clienOF_remoteServer: socket.socket, buffer_list: list):
    """
    Function to be executed after remote socket has closed the connection
    """
    sock_list.clear() # clear the list
    sock_list.append(proxy_server) # add main listener
    clienOF_remoteServer.close() # close conn to remote server
    buffer_list.clear() # clear the buffer
    print("Connection closed...\n") # a simple message


def main() -> None:

    # if enough arg to work on is not provided, print usuage and exit the program 
    if len(sys.argv) !=4:
        print("Current Error: Not enough args provided to work on.")
        usuage(sys.argv[0])
        sys.exit(0)
    
    lhost = str(sys.argv[1])
    lport = int(sys.argv[2])

    rhost = str(sys.argv[3])
    rport = int(sys.argv[4])

    conn = False

    # start listening on the socket (proxy listener)
    server_sock = start_listening(lhost, lport)
    sock_list = [server_sock] # a list for use of select to find readable, writable sock, etc
    buffer_list = [] # a buffer in case data is yet to send but connection has been made

    while True:

        # check the sock state 
        try:
            ready_to_read, ready_to_write, in_error = select.select(sock_list, sock_list, [], 5)
        except Exception as e:
            print(f"Exception: {e.__class__.__name__}, {str(e)}")
            print("Some Error on socket...select")
            break

        # as it is single client server, check if the connection is already made, if not made accept the connection on the listener and connect to remote server 
        if not conn:
            if server_sock in ready_to_read:
                in_sock, _ = accept_connection(server_sock)
                sock_list.append(in_sock)

                client_sock = connect_to((rhost, rport))
                sock_list.append(client_sock)
                conn = True
            continue


        # read data from readble socket (which is remote clinet or server) and write to writable socket (which is also remote client or server), if data is received from remote client, will be sent to remote server and vice-versa
        readable_sock: socket.socket
        writable_sock: socket.socket
        for readable_sock in ready_to_read:
            if not readable_sock is server_sock:
                print(readable_sock.fileno())
                peer = readable_sock.getpeername()
                data = receive_from(readable_sock)
                if data: # send whatever is received
                    print(f"{len(data)} bytes received from {peer}.")
                    hexdump(data)
                    # make sure not to send on the same socket, from where data is recieved and hence is checked as: if sock is not readable_sock 
                    writable_sock = [sock for sock in ready_to_write if not sock is server_sock and not sock is readable_sock]
                    sent = send_to(writable_sock[0], data)
                    if not sent: # connection closed
                        conn = False
                        wrap_up_when_remote_closed_conn(sock_list, server_sock, client_sock, buffer_list)
                        break
                else: # if data not received i.e connection closed
                    conn = False
                    wrap_up_when_remote_closed_conn(sock_list, server_sock, client_sock, buffer_list)



if __name__ == "__main__":
    main()