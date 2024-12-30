#!/bin/python3

import socket
import sys
import select
import threading
import ssl

def usuage(scriptName: str):
    msg =f"""
    This script is designed to be relay server (middle proxy) that will listen on spefic port and
    forwad connection back and forth from remote client and remote server using sockets.

    Usuage: {scriptName} <listen_host> <listen_port> <remote_server> <remote_port> [use_ssl]

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
        # client.setblocking(False)
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


def start_listening(lhost = 'localhost', lport = 9999, blocking_sock = True) -> socket.socket:
    """
    start listening on specified lhost:lport, defaulting to localhost:9999, if value not given
    blocking_sock = True makes the socks blocking and False make it non-blocking, if you are planning to use it with select or selectors make it non-blocking passing blocking_sock = False
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
        if not blocking_sock:
            server_sock.setblocking(False)
        return server_sock
    except Exception as e:
        print(f"Exception: {e.__class__.__name__}, {str(e)}")
        print("surror")
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


def accept_connection(server_sock: socket.socket, blocking_sock = True) -> tuple:
    """
    Accept the connection on the socket which is binded and listening on some addr
    Specify blocking_sock as True if you want to make the incomming sock from server sock blocking (this is default). Specify False if you wanna make same incomming sock non-blocking (useful when you will want to use this in_sock with select or selectors)
    """
    if is_listening(server_sock):
        print(f"Listening on {get_bindAddress(server_sock)} ...")
        in_sock, in_addr = server_sock.accept()
        if not blocking_sock:
            in_sock.setblocking(False)
        print(f"Connected from {in_sock.getpeername()}...")
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


def find_peer(sock: socket.socket)-> tuple:
    """
    return peer i.e ip, port of the other end of connected socket
    return None if not connected or Expection encountered
    """
    try:
        peer = sock.getpeername()
        return peer
    except Exception as e:
        print(f"Exception: {e.__class__.__name__}, {str(e)}")
        print("Error on finding peer...")
        return None


def close_socks(socks: list):
    sock: socket.socket
    for sock in socks:
        sock.close()


def is_client_hello(sock: socket.socket):
    """
    check if client hello has been received on the sock
    it reads frist few byte sequence to identify if ssl handshake has been done, if yes it will check for version compatible
    if handshake has been performed and version is compatible return True else False
    """
    firstbytes = sock.recv(128, socket.MSG_PEEK)
    return (len(firstbytes) >= 3 and
            firstbytes[0] == 0x16 and           # first byte of byte sequence of client hello is \x16
            firstbytes[1:3] in [b"\x03\x00",    # second and third byte sequence for ssl 3.0
                                b"\x03\x01",    # second and third byte sequence for tls 1.0
                                b"\x03\x02",    # second and third byte sequence for tls 1.1
                                b"\x03\x03",    # second and third byte sequence for tls 1.2
                                b"\x02\x00"]    # second and third byte sequence for ssl v2
            )


def does_client_req_ssl(in_sock: socket.socket) -> bool:
    """
    check if in_cock is already ssl enabled, if not check that if the server has received client hello (with the request of ssl)
    if client hello (with ssl) has been received than return True else False
    """
    return (not isinstance(in_sock, ssl.SSLSocket) and is_client_hello(in_sock))


def enable_ssl_both_ways(in_sock: socket.socket, out_sock: socket.socket) -> list:
    """
    as this is proxy server ssl must be enable on incomming and outgoing socket
    """

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.pem")
        in_sock = context.wrap_socket(in_sock, server_side=True)
        print(in_sock.getpeercert())
    except Exception as e:
        print(f"Exception: {e.__class__.__name__}, {str(e)}")
        print("SSL Handshake failed for listening sock..")
        raise


    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.pem")
        out_sock = context.wrap_socket(out_sock)
    except Exception as e:
        print(f"Exception: {e.__class__.__name__}, {str(e)}")
        print("SSL Handshake failed for remote server..")
        raise

    return [in_sock, out_sock]



def proxy_thread(in_sock: socket.socket, rhost: str, rport: str, use_ssl: bool):
    """
    This method is run seperately in a thread as a relay between in_sock (remote_client) and out_sock (remote_server).
    in_sock is what is provided and out_sock is the socket after connect((rhost, rport))
    """
    print("on thread")
    out_sock = connect_to((rhost, rport))
    if out_sock:
        sock_list = [in_sock, out_sock]
        isConnected = True
        # isConnected will show the state where we are connected to both ends, if one connection is closed this will be False and our loop will end 
        while isConnected:
            ready_to_read, ready_to_write, _ = select.select(sock_list, sock_list, [], 100)

            if use_ssl and in_sock in ready_to_read and does_client_req_ssl(in_sock):
                try:
                    sock_list = enable_ssl_both_ways(in_sock, out_sock)
                    in_sock, out_sock = sock_list
                    print("SSL enable on both remote client and remote server.")
                except:
                    isConnected = False
                    break

            ready_to_read, ready_to_write, _ = select.select(sock_list, sock_list, [], 100)


            for readable_sock in ready_to_read:
                peer = find_peer(readable_sock)
                if not peer: # if peer is not find, that is connection is already dead
                    isConnected = False
                    close_socks(sock_list)
                    break
                else: # connection is alive
                    data = receive_from(readable_sock)
                    if not data: # if no data received, that is connection is closed
                        isConnected = False
                        close_socks(sock_list)
                        break
                    else: # connection is alive
                        hexdump(data)
                        # if data is received from remote client forward it to remote server (if it is ready_to_write)
                        if readable_sock == in_sock and out_sock in ready_to_write:
                            sent = send_to(out_sock, data)
                        # if data is received from remote server forward it to remote client (if it is ready_to_read)
                        elif readable_sock == out_sock and in_sock in ready_to_write:
                            sent = send_to(in_sock, data)
                        if not sent: # connection is not active i.e closed
                            isConnected = False
                            close_socks(sock_list)
                            break


# driver code 
def main() -> None:

    # if enough arg to work on is not provided, print usuage and exit the program 
    if len(sys.argv) !=6:
        print("Current Error: Not enough args provided to work on.")
        usuage(sys.argv[0])
        sys.exit(0)
    
    lhost = str(sys.argv[1])
    lport = int(sys.argv[2])

    rhost = str(sys.argv[3])
    rport = int(sys.argv[4])

    if str(sys.argv[5] == "use_ssl"):
        use_ssl = True
    else:
        use_ssl = False

    # start listening on lhost, lport which is actually proxy listener 
    server_sock = start_listening(lhost, lport)

    # endless loop to accept multiple connection until ctrl+c
    if server_sock: 
        try:
            while True:
                # accept connection and forward it to the proxy_thread 
                in_sock, _ = accept_connection(server_sock)
                p_thread = threading.Thread(target=proxy_thread, args=(in_sock, rhost, rport, use_ssl))
                p_thread.start() # i.e p_thread means proxy_thread (named as p_thread to avoid confusion with function name i.e also named as proxy_thread)
        except KeyboardInterrupt:
            print("\nCtrl+C detected, Aborting...")       
            sys.exit(0)


if __name__ == "__main__":
    main()