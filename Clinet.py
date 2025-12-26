import socket
import time
import os

from network_helpers import _read_single_TLS_package
from crypto_helpers import generate_ECDSA_keys_certificate, generate_RSA_keys_certificate
from cryptography.hazmat.primitives import hashes

from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.tls.handshake import *
from scapy.layers.tls.keyexchange import *
from scapy.layers.tls.crypto.suites import *
from scapy.layers.tls.cert import Cert, PrivKey
from scapy.layers.tls.crypto.groups import _tls_named_curves

load_layer("tls")

SERVER_IP = "127.0.0.1"
SERVER_PORT = 4433



def run_tls_client():

    session = tlsSession(connection_end="server")
    
    try:
        cert_name = "client"
        generate_ECDSA_keys_certificate(cert_name)
        # generate_RSA_keys_certificate(cert_name)
        session.client_certs = [Cert(f"{cert_name}.crt")]
        session.client_key = PrivKey(f"{cert_name}.key")

    except Exception as e:
        print(f"[Server] Error loading certificate/key: {e}")


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
            # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.val,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.val,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256.val,
            # TLS_DHE_RSA_WITH_AES_128_CBC_SHA256.val
        ],
        comp=[0],
        ext=[],
        tls_session=session
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

    built_client_hello_record = bytes(client_hello_record)

    client_sock.sendall(built_client_hello_record)
    print("[Client] Sent ClientHello")
    client_hello_parsed_record = TLS(built_client_hello_record, tls_session=session)
    client_hello_parsed_record.show()
    print('\n')
    # ===============================


    

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
    
    
   
    # =======|  ClientKeyExchange  |=======
    # if session.server_kx_pubkey:
        
    #     # session.client_kx_ffdh_params = session.server_kx_pubkey.parameters()
    #     session.client_kx_ecdh_params = [c for c in _tls_named_curves.keys() if _tls_named_curves[c] == session.kx_group][0]
        
    # else:
    #     raise RuntimeError("Did not recieve server public key")

    
    # session.client_kx_ffdh_params = session.server_kx_pubkey.parameters()
    # DHE_params = ClientDiffieHellmanPublic(tls_session=session)
    session.client_kx_ecdh_params = [c for c in _tls_named_curves.keys() if _tls_named_curves[c] == session.kx_group][0]
    DHE_params = ClientECDiffieHellmanPublic(tls_session=session)
    DHE_params.fill_missing()

    cke_msg = TLSClientKeyExchange(exchkeys=DHE_params, tls_session=session)

    cke_record = TLS(
        type=22,
        version=0x0303,
        msg=[cke_msg],
        tls_session=session
    )

    built_cke_record = bytes(cke_record)

    client_sock.sendall(built_cke_record)
    print("[Client] Sent ClientKeyExchange")
    cke_parsed_record = TLS(built_cke_record, tls_session=session)
    cke_parsed_record.show()
    print('\n')
    # ===============================
    





    # =======|  Client: ChangeCipherSpec  |=======
    ccs_msg = TLSChangeCipherSpec(tls_session=session)
    
    ccs_record = TLS(
        type=20,
        version=0x0303,
        msg=ccs_msg,
        tls_session=session
    )

    built_css_record = bytes(ccs_record)

    client_sock.sendall(built_css_record)
    print("[Client] Sent ChangeCipherSpec")
    css_parsed_record = TLS(built_css_record, tls_session=session)
    css_parsed_record.show()
    print('\n')
    # ===============================
    
    for msg in session.handshake_messages:
        hash = hashes.Hash(hashes.SHA256())
        hash.update(msg)
        print(hash.finalize())

    
    print(f"Client session pwcs:\n {session.pwcs}\n")
    print(f"Server public key:\n {session.server_kx_pubkey}\n")
    print(f"Pre-master key:\n {session.pre_master_secret}\n")
    print(f"Master key:\n {session.master_secret}\n")

    
    # =======|  Client: Finished  |=======
    finished_msg = TLSFinished(tls_session=session)
    
    finished_record = TLS(
        type=22,
        version=0x0303,
        msg=[finished_msg],
        tls_session=session
    )
    
    built_finished_record = bytes(finished_record)
    
    client_sock.sendall(built_finished_record)
    print("[Client] Sent Finished (encrypted)")
    finished_parsed_record = TLS(built_finished_record, tls_session=session)
    finished_parsed_record.show()
    print('\n')
    # ===============================
    
    
    # iv, efrag 
    # session.rcs.cipher.iv = iv
    # session.rcs.cipher.decrypt(s)
    


    # =======|  Server: ChangeCipherSpec  |=======
    data = _read_single_TLS_package(client_sock)
    server_ccs_record = TLS(data, tls_session=session)
    print("[Client] Received ChangeCipherSpec from server")
    server_ccs_record.show()
    print('\n')
    # ===============================
    


    print(session.rcs.seq_num)
    # =======|  Server: Finished  |=======
    data = _read_single_TLS_package(client_sock)
    server_finished_record = TLS(data, tls_session=session)
    print("[Client] Received Finished from server")
    server_finished_record.show()
    print('\n')
    # ===============================
    print(session.rcs.seq_num)
    


    # =======|  Client: ApplicationData  |=======
    request_data = b"aaaabbbbccccddddffffeeeekkkktttt"
    
    app_data_msg = TLSApplicationData(data=request_data, tls_session=session)
    
    app_data_record = TLS(
        type=23,
        version=0x0303,
        msg=app_data_msg,
        tls_session=session
    )
    
    built_app_data_record = bytes(app_data_record)

    client_sock.sendall(built_app_data_record)
    print("[Client] Sent ApplicationData (encrypted)")
    app_data_parsed_record = TLS(built_app_data_record, tls_session=session)
    app_data_parsed_record.show()
    print('\n')
    # ===============================
    

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
