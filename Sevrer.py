import socket
import time
import os

from network_helpers import _read_single_TLS_package
from crypto_helpers import generate_ECDSA_keys_certificate, generate_RSA_keys_certificate, generate_DHE_piece

from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.tls.handshake import *
from scapy.layers.tls.keyexchange import *
from scapy.layers.tls.crypto.suites import *
from scapy.layers.tls.cert import Cert, PrivKey
from scapy.layers.tls.handshake import _tls_hash_sig

load_layer("tls")

SERVER_IP = "127.0.0.1"
SERVER_PORT = 4433

def run_tls_server():

    session = tlsSession(connection_end="server")

    try:
        cert_name = "server"
        generate_ECDSA_keys_certificate(cert_name)
        session.server_certs = [Cert(f"{cert_name}.crt")]
        session.server_key = PrivKey(f"{cert_name}.key")

    except Exception as e:
        print(f"[Server] Error loading certificate/key: {e}")


    session.pwcs = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    if not hasattr(session.pwcs, 'key_exchange'):
        session.pwcs.key_exchange = session.pwcs.kx_alg
    session.selected_sig_alg = [c for c in _tls_hash_sig.keys() if _tls_hash_sig[c] == "sha256+ecdsa"][0]
    print(session.selected_sig_alg)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((SERVER_IP, SERVER_PORT))
    server_sock.listen(1)
    
    print(f"[Server] Listening on {SERVER_IP}:{SERVER_PORT}")

    conn, addr = server_sock.accept()
    session.sock = conn
    print(f"[Server] Connection from {addr}")

    
    # =======|  ClientHello  |=======
    data = _read_single_TLS_package(conn)
    client_hello_record = TLS(data, tls_session=session)

    print("[Server] Received ClientHello")
    client_hello_record.show()
    print('\n')
    # ===============================


    session = client_hello_record.tls_session
    

    # =======|  ServerHello  |=======
    server_hello = TLSServerHello(
        version=0x0303,  # TLS 1.2
        gmt_unix_time=int(time.time()),
        random_bytes=os.urandom(28),
        sid=os.urandom(32),
        cipher=[
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256.val
            ], 
        comp=0
    )

    server_hello_record = TLS(
        type=22, 
        version=0x0303,
        msg=[server_hello],
        tls_session=session
    )
    
    # TODO wtf?
    server_random = server_hello.gmt_unix_time.to_bytes(4, 'big') + server_hello.random_bytes
    session.server_random = server_random

    conn.sendall(bytes(server_hello_record))
    print("[Server] Sent ServerHello")
    server_hello_record.show()
    print('\n')
    # ===============================


    session = server_hello_record.tls_session
    

    # =======|  Certificate  |=======
    certificate_msg = TLSCertificate(
        certs=session.server_certs
    )

    cert_record = TLS(
        type=22,
        version=0x0303,
        msg=[certificate_msg],
        tls_session=session
    )
    
    conn.sendall(bytes(cert_record))
    print("[Server] Sent Certificate")
    cert_record.show()
    print('\n')
    # ===============================


    session = cert_record.tls_session


    # =======|  ServerKeyExchange  |=======
    p_bytes, g_bytes, y_bytes, privkey = generate_DHE_piece()
    # session.server_kx_privkey = privkey
    # DHE_params = ServerDHParams(dh_p=p_bytes, dh_g=g_bytes, dh_Ys=y_bytes, tls_session=session)

    
    DHE_params = ServerECDHNamedCurveParams(tls_session=session)
    DHE_params.fill_missing()


    session.server_kx_pubkey = session.server_kx_privkey.public_key()
    ske_msg = TLSServerKeyExchange(params=DHE_params)

    ske_record = TLS(
        type=22,
        version=0x0303,
        msg=[ske_msg],
        tls_session=session
    )



    conn.sendall(bytes(ske_record))
    print("[Server] Sent ServerKeyExchange")
    ske_record.show()
    print('\n')
    # ===============================



    session = ske_record.tls_session

    print(session.selected_sig_alg)
    print(session.kx_group)
    print(session.server_kx_privkey)
    print(session.server_kx_pubkey)

    # =======|  ServerHelloDone  |=======
    server_done_msg = TLSServerHelloDone()
    
    server_done_record = TLS(
        type=22,
        version=0x0303,
        msg=[server_done_msg],
        tls_session=session
    )

    conn.sendall(bytes(server_done_record))
    print("[Server] Sent ServerHelloDone")
    server_done_record.show()
    print('\n')
    # ===============================


    session = server_done_record.tls_session
    

    # =======|  ClientKeyExchange  |=======
    data = _read_single_TLS_package(conn)
    cke_record = TLS(
        data, 
        tls_session=session
    )
    print("[Server] Received ClientKeyExchange")
    cke_record.show()
    print('\n')
    # ===============================


    session = cke_record.tls_session
    

    # =======|  Client: ChangeCipherSpec  |=======
    data = _read_single_TLS_package(conn)

    ccs_record = TLS(data, tls_session=session)
    print("[Server] Received ChangeCipherSpec from client")
    ccs_record.show()
    print('\n')
    # ===============================


    session = ccs_record.tls_session
    


    # =======|  Client: Finished  |=======
    data = _read_single_TLS_package(conn)

    finished_record = TLS(data, tls_session=session)
    print("[Server] Received Finished from client")
    finished_record.show()
    print('\n')
    # ===============================


    session = finished_record.tls_session
    
    
    # =======|  Server: ChangeCipherSpec  |=======
    ccs_msg = TLSChangeCipherSpec()
    
    ccs_send_record = TLS(
        type=20,
        version=0x0303,
        msg=ccs_msg,
        tls_session=session
    )
    
    conn.sendall(bytes(ccs_send_record))
    print("[Server] Sent ChangeCipherSpec")
    ccs_send_record.show()
    print('\n')
    # ===============================


    session = ccs_send_record.tls_session
    

    # =======|  Server: Finished  |=======
    finished_msg = TLSFinished()
    
    finished_send_record = TLS(
        type=22,
        version=0x0303,
        msg=[finished_msg],
        tls_session=session
    )
    

    conn.sendall(bytes(finished_send_record))
    print("[Server] Sent Finished (encrypted)")
    finished_send_record.show()
    print('\n')
    # ===============================


    session = finished_send_record.tls_session
    

    # =======|  Client: ApplicationData  |=======
    data = _read_single_TLS_package(conn)
    app_data_record = TLS(data, tls_session=session)
    print("[Server] Received ApplicationData:")
    
    if app_data_record.haslayer(TLSApplicationData):
        app_data_record.show()
        decrypted_data = app_data_record[TLSApplicationData].data
        print(f"  Decrypted: {decrypted_data}")

    print('\n')
    # ===============================


    session = app_data_record.tls_session
    

    # =======|  Server: ApplicationData  |=======
    response_data = b"$erverne Nebo 43kae na 3aBTpA"
    
    app_data_msg = TLSApplicationData(data=response_data)
    
    app_data_send_record = TLS(
        type=23,
        version=0x0303,
        msg=app_data_msg,
        tls_session=session
    )
    
    conn.sendall(bytes(app_data_send_record))
    print("[Server] Sent ApplicationData (encrypted)")
    app_data_send_record.show()
    print('\n')
    # ===============================



    conn.close()
    server_sock.close()
    print("[Server] Connection closed")



if __name__ == "__main__":
    run_tls_server()
