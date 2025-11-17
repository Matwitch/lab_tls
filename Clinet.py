import socket
from network_helpers import _read_single_TLS_package

import time
import os
from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.tls.crypto.suites import *
from scapy.layers.tls.session import tlsSession

from cryptography.hazmat.primitives.asymmetric import dh

load_layer("tls")

SERVER_IP = "127.0.0.1"
SERVER_PORT = 4433




def run_tls_client():
    # Create TLS session context
    session = tlsSession(connection_end="client")
    
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((SERVER_IP, SERVER_PORT))
    print(f"[Client] Connected to {SERVER_IP}:{SERVER_PORT}")


    # Step 1: Build and send ClientHello
    client_hello = TLSClientHello(
        version=0x0303,  # TLS 1.2
        gmt_unix_time=int(time.time()),
        random_bytes=os.urandom(28),
        sid=b'',
        ciphers=[
            TLS_DHE_DSS_WITH_AES_128_CBC_SHA256.val
        ],
        comp=[0],
        ext=[]
    )
    
    client_hello_record = TLS(
        type=22,
        version=0x0303,  # TLS 1.0 in record header (for compatibility)
        msg=[client_hello],
        tls_session=session
    )


    client_sock.sendall(bytes(client_hello_record))
    print("[Client] Sent ClientHello")
    
    # Update session after sending
    session = client_hello_record.tls_session.mirror()
    
    # Step 2: Receive ServerHello
    data = _read_single_TLS_package(client_sock)
    server_hello_record = TLS(
        data, 
        tls_session=session
        )
    print("[Client] Received ServerHello")
    
    # Session automatically extracts server random and cipher suite
    session = server_hello_record.tls_session
    
    # Step 3: Receive Certificate
    data = _read_single_TLS_package(client_sock)
    cert_record = TLS(
        data, 
        tls_session=session
        )
    print("[Client] Received Certificate")
    
    # Session automatically extracts server certificate
    session = cert_record.tls_session
    
    # Step 4: Receive ServerKeyExchange (if present)
    data = _read_single_TLS_package(client_sock)
    ske_record = TLS(
        data, 
        tls_session=session
        )
    print("[Client] Received ServerKeyExchange")
    print(bytes(ske_record))

    # Session automatically extracts server public key
    session = ske_record.tls_session

    # Step 5: Receive ServerHelloDone
    data = _read_single_TLS_package(client_sock)
    server_done_record = TLS(
        data, 
        tls_session=session
        )
    print("[Client] Received ServerHelloDone")
    
    session = server_done_record.tls_session.mirror()
    
    # Step 6: Build and send ClientKeyExchange
    session.client_kx_ffdh_params=dh.generate_parameters(generator=2, key_size=2048)
    DHE_params = ClientDiffieHellmanPublic(tls_session=session).fill_missing()
    cke_msg = TLSClientKeyExchange()

    cke_record = TLS(
        type=22,
        version=0x0303,
        msg=[cke_msg],
        tls_session=session
    )

    cke_record.show2()

    client_sock.sendall(bytes(cke_record))
    print("[Client] Sent ClientKeyExchange")
    session = cke_record.tls_session
    # TLSSession will automatically generate pre-master secret
    # and encrypt it with server's public key from the certificate

    

    
    # Step 7: Send ChangeCipherSpec
    ccs_msg = TLSChangeCipherSpec()
    
    ccs_record = TLS(
        type=20,
        version=0x0303,
        msg=ccs_msg,
        tls_session=session
    )
    
    client_sock.sendall(bytes(ccs_record))
    print("[Client] Sent ChangeCipherSpec")
    
    # Session automatically activates pending cipher state
    session = ccs_record.tls_session
    
    # Step 8: Send Finished (encrypted with negotiated keys)
    # TLSSession automatically computes verify_data and encrypts
    finished_msg = TLSFinished()
    
    finished_record = TLS(
        type=22,
        version=0x0303,
        msg=[finished_msg],
        tls_session=session
    )
    
    client_sock.sendall(bytes(finished_record))
    print("[Client] Sent Finished (encrypted)")
    
    session = finished_record.tls_session.mirror()
    
    # Step 9: Receive ChangeCipherSpec from server
    data = _read_single_TLS_package(client_sock)
    server_ccs_record = TLS(data, tls_session=session)
    print("[Client] Received ChangeCipherSpec from server")
    
    session = server_ccs_record.tls_session
    
    # Step 10: Receive Finished from server (encrypted)
    data = _read_single_TLS_package(client_sock)
    server_finished_record = TLS(data, tls_session=session)
    print("[Client] Received Finished from server")
    
    # Session automatically decrypts and verifies Finished
    session = server_finished_record.tls_session.mirror()
    
    # Step 11: Send ApplicationData
    request_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    app_data_msg = TLSApplicationData(data=request_data)
    
    app_data_record = TLS(
        type=23,
        version=0x0303,
        msg=app_data_msg,
        tls_session=session
    )
    
    client_sock.sendall(bytes(app_data_record))
    print("[Client] Sent ApplicationData (encrypted)")
    
    session = app_data_record.tls_session.mirror()
    
    # Step 12: Receive ApplicationData
    data = _read_single_TLS_package(client_sock)
    response_record = TLS(data, tls_session=session)
    print("[Client] Received ApplicationData:")
    
    # Session automatically decrypts application data
    if response_record.haslayer(TLSApplicationData):
        decrypted_data = response_record[TLSApplicationData].data
        print(f"  Decrypted: {decrypted_data}")
    
    client_sock.close()
    print("[Client] Connection closed")

if __name__ == "__main__":
    run_tls_client()
