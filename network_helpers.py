import socket
from scapy.layers.tls.all import *
from scapy.layers.tls.crypto.suites import *



def _read_TLS_header(sock: socket):
    sock.settimeout(240)
    header = bytearray(5)

    for i in range(5):
        try:
            header[i] = sock.recv(1)[0]
        except socket.timeout:
            raise RuntimeError("Socket TLS Header pending timeout")

    if not (0x14 <= header[0] <= 0x18):
        raise RuntimeError(f"Incorrect TLS header format: {header[0]} is not valid Content Type")
    if not (0x3 <= header[1] <= 0x4):
        raise RuntimeError(f"Incorrect TLS header format: {header[1]} is not valid TLS Verison")
    if not (0x3 <= header[2] <= 0x4):
        raise RuntimeError(f"Incorrect TLS header format: {header[2]} is not valid TLS Verison")

    length = int.from_bytes(header[3:5], 'big')

    sock.settimeout(None)

    return bytes(header), length

def _read_single_TLS_package(sock):
    header, length = _read_TLS_header(sock)
    
    content = bytearray()

    sock.settimeout(240)
    while len(content) < length:
        try:
            content.extend(sock.recv(length - len(content)))
        except socket.timeout:
            raise RuntimeError("Socket TLS Package Content pending timeout")
    
    sock.settimeout(None)

    return header + bytes(content)

