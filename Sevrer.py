import socket
from network_helpers import _read_single_TLS_package

import time
import os
from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.tls.handshake import *
from scapy.layers.tls.keyexchange import *
from scapy.layers.tls.crypto.suites import *


load_layer("tls")

SERVER_IP = "127.0.0.1"
SERVER_PORT = 4433

def run_tls_server():
    # Create TLS session context
    session = tlsSession(connection_end="server")
    
    # Load server certificate and private key
    # You'll need actual certificate and key files
    from scapy.layers.tls.cert import Cert, PrivKey
    
    session.server_certs = [Cert("server.der")]
    session.server_key = PrivKey("server.key")
    
    # For demonstration, we'll use dummy cert/key
    # In production, load real certificates
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((SERVER_IP, SERVER_PORT))
    server_sock.listen(1)
    
    print(f"[Server] Listening on {SERVER_IP}:{SERVER_PORT}")
    conn, addr = server_sock.accept()
    print(f"[Server] Connection from {addr}")
    
    # Step 1: Receive and parse ClientHello
    data = _read_single_TLS_package(conn)
    
    client_hello_record = TLS(data, tls_session=session)
    print("[Server] Received ClientHello")
    client_hello_record.show2()
    
    # The session is automatically updated with client random and other parameters
    # Now mirror the session for sending server responses
    session = client_hello_record.tls_session.mirror()
    
    # Step 2: Build and send ServerHello
    server_hello = TLSServerHello(
        version=0x0303,  # TLS 1.2
        gmt_unix_time=int(time.time()),
        random_bytes=os.urandom(28),
        sid=os.urandom(32),
        cipher=[
            TLS_DHE_DSS_WITH_AES_128_CBC_SHA256.val
            ], 
        comp=0
    )
    
    server_hello_record = TLS(
        type=22, 
        version=0x0303,
        msg=[server_hello],
        tls_session=session
    )
    
    conn.sendall(bytes(server_hello_record))
    print("[Server] Sent ServerHello")
    
    # Update session after building ServerHello
    session = server_hello_record.tls_session
    
    # Step 3: Send Certificate
    # Load actual certificate or use a dummy one
    certificate_msg = TLSCertificate(
        certs=session.server_certs  # DER-encoded certificate
    )
    
    cert_record = TLS(
        type=22,
        version=0x0303,
        msg=[certificate_msg],
        tls_session=session
    )
    
    conn.sendall(bytes(cert_record))
    print("[Server] Sent Certificate")
    session = cert_record.tls_session
    
    # Step 4: Send ServerKeyExchange (optional for RSA key exchange)
    # For DHE/ECDHE, you would send ServerKeyExchange here

    DHE_params = ServerDHParams(tls_session=session)
    ske_msg = TLSServerKeyExchange(params=DHE_params, tls_session=session)
    

    ske_record = TLS(
        type=22,
        version=0x0303,
        msg=[ske_msg],
        tls_session=session
    )
    
    
    conn.sendall(bytes(ske_record))
    print("[Server] Sent ServerKeyExchange")
    print(bytes(ske_record))
    ske_record.show2()
    session = ske_record.tls_session


    # For plain RSA, this step is skipped
    
    # Step 5: Send ServerHelloDone
    server_done_msg = TLSServerHelloDone()
    
    server_done_record = TLS(
        type=22,
        version=0x0303,
        msg=[server_done_msg],
        tls_session=session
    )

    conn.sendall(bytes(server_done_record))
    print("[Server] Sent ServerHelloDone")
    session = server_done_record.tls_session.mirror()
    
    # Step 6: Receive ClientKeyExchange
    data = _read_single_TLS_package(conn)
    cke_record = TLS(
        data, 
        tls_session=session
        )
    print("[Server] Received ClientKeyExchange")
    
    cke_record.show2()
    # Session automatically extracts pre-master secret and computes master secret
    session = cke_record.tls_session
    
    # Step 7: Receive ChangeCipherSpec from client
    data = _read_single_TLS_package(conn)
    ccs_record = TLS(data, tls_session=session)
    print("[Server] Received ChangeCipherSpec from client")
    
    # Session automatically updates cipher state
    session = ccs_record.tls_session
    
    # Step 8: Receive Finished from client (encrypted)
    data = _read_single_TLS_package(conn)
    finished_record = TLS(data, tls_session=session)
    print("[Server] Received Finished from client")
    
    # Session automatically decrypts and verifies Finished message
    session = finished_record.tls_session.mirror()
    
    # Step 9: Send ChangeCipherSpec
    ccs_msg = TLSChangeCipherSpec()
    
    ccs_send_record = TLS(
        type=20,
        version=0x0303,
        msg=ccs_msg,
        tls_session=session
    )
    
    conn.sendall(bytes(ccs_send_record))
    print("[Server] Sent ChangeCipherSpec")
    session = ccs_send_record.tls_session
    
    # Step 10: Send Finished (encrypted with negotiated keys)
    # TLSSession automatically computes verify_data and encrypts
    finished_msg = TLSFinished()
    
    finished_send_record = TLS(
        type=22,
        version=0x0303,
        msg=[finished_msg],
        tls_session=session
    )
    
    conn.sendall(bytes(finished_send_record))
    print("[Server] Sent Finished (encrypted)")
    session = finished_send_record.tls_session.mirror()
    
    # Step 11: Receive ApplicationData
    data = _read_single_TLS_package(conn)
    app_data_record = TLS(data, tls_session=session)
    print("[Server] Received ApplicationData:")
    
    # Session automatically decrypts application data
    if app_data_record.haslayer(TLSApplicationData):
        decrypted_data = app_data_record[TLSApplicationData].data
        print(f"  Decrypted: {decrypted_data}")
    
    session = app_data_record.tls_session.mirror()
    
    # Step 12: Send ApplicationData
    response_data = b"HTTP/1.1 200 OK\r\n\r\nHello from TLS server!"
    
    app_data_msg = TLSApplicationData(data=response_data)
    
    app_data_send_record = TLS(
        type=23,
        version=0x0303,
        msg=app_data_msg,
        tls_session=session
    )
    
    conn.sendall(bytes(app_data_send_record))
    print("[Server] Sent ApplicationData (encrypted)")
    
    conn.close()
    server_sock.close()
    print("[Server] Connection closed")

if __name__ == "__main__":
    run_tls_server()
