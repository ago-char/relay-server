# Intro
- A basic relay server inspired by *tcpproxy* project found on github.
- A part of `socket` learning project
- Working with some clients like ftp, http, ssh, etc.
- `ssl` certificate validation is yet to be updated but simple chat server can be wrapped up with ssl
- `ssl` feature is restricted to the use of same `server-cert.pem` and `server-key.pem` for all proxy, client and server which is needed to be updated
- multi connections accepeted

## Usuage
usage: relay.py [-h] -lh LISTEN_HOST -lp LISTEN_PORT -rh REMOTE_HOST -rp
                REMOTE_PORT [--ssl]

options:
  -h, --help            show this help message and exit
  -lh LISTEN_HOST, --listen-host LISTEN_HOST
                        IP or hostname of listening host
  -lp LISTEN_PORT, --listen-port LISTEN_PORT
                        Port of listening host
  -rh REMOTE_HOST, --remote-host REMOTE_HOST
                        IP or hostname of remote host
  -rp REMOTE_PORT, --remote-port REMOTE_PORT
                        Port of remote host
  --ssl                 Use SSL for connection


## Requirements/Installation
- Make sure all the imported modules are installed in your system.
(`socket, sys, select, threading, ssl, argparse`)
