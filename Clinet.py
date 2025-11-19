import socket
import time
import os

from network_helpers import _read_single_TLS_package
from crypto_helpers import generate_ECDSA_keys_certificate, generate_RSA_keys_certificate

from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.tls.handshake import *
from scapy.layers.tls.keyexchange import *
from scapy.layers.tls.crypto.suites import *
from scapy.layers.tls.cert import Cert, PrivKey


load_layer("tls")

SERVER_IP = "127.0.0.1"
SERVER_PORT = 4433



def run_tls_client():

    session = tlsSession(connection_end="client")
    
    try:
        cert_name = "client"
        generate_ECDSA_keys_certificate(cert_name)
        session.client_certs = [Cert(f"{cert_name}.crt")]
        session.client_key = PrivKey(f"{cert_name}.key")

    except Exception as e:
        print(f"[Server] Error loading certificate/key: {e}")

    # session.pwcs = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256


    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((SERVER_IP, SERVER_PORT))
    session.sock = client_sock
    print(f"[Client] Connected to {SERVER_IP}:{SERVER_PORT}")



    # =======|  ClientHello  |=======
    client_hello = TLSClientHello(
        version=0x0303,  # TLS 1.2
        gmt_unix_time=int(time.time()),
        random_bytes=os.urandom(28),
        sid=b'',
        ciphers=[
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256.val
        ],
        comp=[0],
        ext=[]
    )
    
    client_hello_record = TLS(
        type=22,
        version=0x0303,  
        msg=[client_hello],
        tls_session=session
    )
    

    # TODO wtf?
    client_random = client_hello.gmt_unix_time.to_bytes(4, 'big') + client_hello.random_bytes
    session.client_random = client_random

    client_sock.sendall(bytes(client_hello_record))
    print("[Client] Sent ClientHello")
    client_hello.show()
    print('\n')
    # ===============================


    session = client_hello_record.tls_session
    

    # =======|  ServerHello  |=======
    data = _read_single_TLS_package(client_sock)
    server_hello_record = TLS(
        data, 
        tls_session=session
    )
    print("[Client] Received ServerHello")
    server_hello_record.show()
    print('\n')
    # ===============================


    
    session = server_hello_record.tls_session
    

    # =======|  Certificate  |=======
    data = _read_single_TLS_package(client_sock)
    cert_record = TLS(
        data, 
        tls_session=session
    )
    print("[Client] Received Certificate")
    cert_record.show()
    print('\n')
    # ===============================


    session = cert_record.tls_session
    

    # =======|  ServerKeyExchange  |=======
    data = _read_single_TLS_package(client_sock)
    ske_record = TLS(
        data, 
        tls_session=session
    )
    print("[Client] Received ServerKeyExchange")
    ske_record.show()
    print('\n')
    # ===============================


    session = ske_record.tls_session  


    # =======|  ServerHelloDone  |=======
    data = _read_single_TLS_package(client_sock)
    server_done_record = TLS(
        data, 
        tls_session=session
    )
    print("[Client] Received ServerHelloDone")
    server_done_record.show()
    print('\n')
    # ===============================
    
    session = server_done_record.tls_session
    
   
    # =======|  ClientKeyExchange  |=======
    if session.server_kx_pubkey:
        session.client_kx_ffdh_params = session.server_kx_pubkey.parameters()
        # session.client_kx_privkey = session.client_kx_ffdh_params.generate_private_key()
        
    else:
        raise RuntimeError("Did not recieve server public key")
    
    DHE_params = ClientDiffieHellmanPublic(tls_session=session)
    cke_msg = TLSClientKeyExchange(exchkeys=DHE_params)

    cke_record = TLS(
        type=22,
        version=0x0303,
        msg=[cke_msg],
        tls_session=session
    )

    client_sock.sendall(bytes(cke_record))
    print("[Client] Sent ClientKeyExchange")
    cke_record.show()
    print('\n')
    # ===============================
    

    session = cke_record.tls_session

    # print(f"Client key: {session.client_kx_privkey}")
    # print(f"Pre-master key: {session.pre_master_secret}")
    # print(f"Master key: {session.master_secret}")
    
    # =======|  Client: ChangeCipherSpec  |=======
    ccs_msg = TLSChangeCipherSpec()
    
    ccs_record = TLS(
        type=20,
        version=0x0303,
        msg=ccs_msg,
        tls_session=session
    )
    
    client_sock.sendall(bytes(ccs_record))
    print("[Client] Sent ChangeCipherSpec")
    ccs_record.show()
    print('\n')
    # ===============================
    

    session = ccs_record.tls_session
    
    
    # =======|  Client: Finished  |=======
    finished_msg = TLSFinished()
    
    finished_record = TLS(
        type=22,
        version=0x0303,
        msg=[finished_msg],
        tls_session=session
    )
    
    client_sock.sendall(bytes(finished_record))
    print("[Client] Sent Finished (encrypted)")
    finished_record.show()
    print('\n')
    # ===============================
    

    session = finished_record.tls_session
    

    # =======|  Server: ChangeCipherSpec  |=======
    data = _read_single_TLS_package(client_sock)
    server_ccs_record = TLS(data, tls_session=session)
    print("[Client] Received ChangeCipherSpec from server")
    server_ccs_record.show()
    print('\n')
    # ===============================
    

    session = server_ccs_record.tls_session
    

    # =======|  Server: Finished  |=======
    data = _read_single_TLS_package(client_sock)
    server_finished_record = TLS(data, tls_session=session)
    print("[Client] Received Finished from server")
    server_finished_record.show()
    print('\n')
    # ===============================
    
    
    session = server_finished_record.tls_session
    

    # =======|  Client: ApplicationData  |=======
    request_data = b"|<Li3Ntove Nebo Yde Na3aD"
    
    app_data_msg = TLSApplicationData(data=request_data)
    
    app_data_record = TLS(
        type=23,
        version=0x0303,
        msg=app_data_msg,
        tls_session=session
    )
    
    client_sock.sendall(bytes(app_data_record))
    print("[Client] Sent ApplicationData (encrypted)")
    app_data_record.show()
    print('\n')
    # ===============================
    

    session = app_data_record.tls_session
    

    # =======|  Server: ApplicationData  |=======
    data = _read_single_TLS_package(client_sock)
    response_record = TLS(data, tls_session=session)
    print("[Client] Received ApplicationData:")
    
    if response_record.haslayer(TLSApplicationData):
        response_record.show()
    
    print('\n')
    # ===============================


    client_sock.close()
    print("[Client] Connection closed")

if __name__ == "__main__":
    run_tls_client()
