import socket
import time
import os

from network_helpers import _read_single_TLS_package
from crypto_helpers import generate_ECDSA_keys_certificate, generate_RSA_keys_certificate, generate_DHE_piece
from cryptography.hazmat.primitives import hashes

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
        # generate_RSA_keys_certificate(cert_name)
        session.server_certs = [Cert(f"{cert_name}.crt")]
        session.server_key = PrivKey(f"{cert_name}.key")

    except Exception as e:
        print(f"[Server] Error loading certificate/key: {e}")


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



    # =======|  ServerHello  |=======
    server_hello = TLSServerHello(
        version=0x0303,  # TLS 1.2
        gmt_unix_time=int(time.time()),
        random_bytes=os.urandom(28),
        sid=os.urandom(32),
        cipher=[
            # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.val,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.val,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256.val,
            # TLS_DHE_RSA_WITH_AES_128_CBC_SHA256.val,
            ], 
        comp=0,
        tls_session=session
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

    built_server_hello_record = bytes(server_hello_record)

    conn.sendall(built_server_hello_record)
    print("[Server] Sent ServerHello")
    server_hello_parsed_record = TLS(built_server_hello_record, tls_session=session)
    server_hello_parsed_record.show()
    print('\n')
    # ===============================




    # =======|  Certificate  |=======
    certificate_msg = TLSCertificate(
        certs=session.server_certs,
        tls_session=session
    )

    cert_record = TLS(
        type=22,
        version=0x0303,
        msg=[certificate_msg],
        tls_session=session
    )

    built_cert_record = bytes(cert_record)
    conn.sendall(built_cert_record)
    print("[Server] Sent Certificate")
    cert_parsed_record = TLS(built_cert_record, tls_session=session)
    cert_parsed_record.show()
    print('\n')
    # ===============================



    # =======|  ServerKeyExchange  |=======
    # p_bytes, g_bytes, y_bytes, privkey = generate_DHE_piece()
    # session.server_kx_privkey = privkey
    # DHE_params = ServerDHParams(dh_p=p_bytes, dh_g=g_bytes, dh_Ys=y_bytes, tls_session=session)

    
    DHE_params = ServerECDHNamedCurveParams(tls_session=session)
    DHE_params.fill_missing()
    # DHE_params = ServerDHParams(tls_session=session)

    ske_msg = TLSServerKeyExchange(params=DHE_params, tls_session=session)

    ske_record = TLS(
        type=22,
        version=0x0303,
        msg=[ske_msg],
        tls_session=session
    )

    built_ske_record = bytes(ske_record)

    conn.sendall(built_ske_record)
    print("[Server] Sent ServerKeyExchange")

    ske_parsed_record = TLS(built_ske_record, tls_session=session)

    ske_parsed_record.show()
    print('\n')
    # ===============================



    # =======|  ServerHelloDone  |=======
    server_done_msg = TLSServerHelloDone(tls_session=session)
    
    server_done_record = TLS(
        type=22,
        version=0x0303,
        msg=[server_done_msg],
        tls_session=session
    )

    built_server_done_record = bytes(server_done_record)
    conn.sendall(built_server_done_record)
    print("[Server] Sent ServerHelloDone")
    server_done_parsed_record = TLS(built_server_done_record, tls_session=session)
    server_done_parsed_record.show()
    print('\n')
    # ===============================



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




    # =======|  Client: ChangeCipherSpec  |=======
    data = _read_single_TLS_package(conn)

    ccs_record = TLS(
        data, 
        tls_session=session
    )
    print("[Server] Received ChangeCipherSpec from client")
    ccs_record.show()
    print('\n')
    # ===============================


    print(f"Server session pwcs:\n {session.pwcs}\n")
    print(f"Client public key:\n {session.client_kx_pubkey}\n")
    print(f"Pre-master key:\n {session.pre_master_secret}\n")
    print(f"Master key:\n {session.master_secret}\n")
    print(f"Encrypt-then-MAC:\n {session.encrypt_then_mac}")



    # =======|  Client: Finished  |=======
    data = _read_single_TLS_package(conn)

    finished_record = TLS(
        data, 
        tls_session=session
    )
    print("[Server] Received Finished from client")
    finished_record.show()
    print('\n')
    # ===============================


    
    # =======|  Server: ChangeCipherSpec  |=======
    ccs_msg = TLSChangeCipherSpec(tls_session=session)
    
    server_ccs_record = TLS(
        type=20,
        version=0x0303,
        msg=[ccs_msg],
        tls_session=session
    )
    
    built_server_ccs_record = bytes(server_ccs_record)
    conn.sendall(built_server_ccs_record)
    print("[Server] Sent ChangeCipherSpec")
    server_ccs_parsed_record = TLS(built_server_ccs_record, tls_session=session)
    server_ccs_parsed_record.show()
    print('\n')
    # ===============================


    for msg in session.handshake_messages:
        hash = hashes.Hash(hashes.SHA256())
        hash.update(msg)
        print(hash.finalize())

    print(session.wcs.seq_num)
    # =======|  Server: Finished  |=======
    finished_msg = TLSFinished(tls_session=session)
    
    server_finished_record = TLS(
        type=22,
        version=0x0303,
        msg=[finished_msg],
        tls_session=session
    )

    built_server_finished_record = bytes(server_finished_record)

    conn.sendall(bytes(built_server_finished_record))
    print("[Server] Sent Finished (encrypted)")
    server_finished_parsed_record = TLS(built_server_finished_record, tls_session=session)
    server_finished_parsed_record.show()
    print('\n')
    # ===============================
    print(session.rcs.seq_num)



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



    # =======|  Server: ApplicationData  |=======
    response_data = b"$erverne Nebo 43kae na 3aBTpA"
    
    app_data_msg = TLSApplicationData(data=response_data, tls_session=session)
    
    server_app_data_record = TLS(
        bytes(TLS(
            type=23,
            version=0x0303,
            msg=app_data_msg,
            tls_session=session
        )),
        tls_session=session
    )
    built_server_app_data_record = bytes(server_app_data_record)
    conn.sendall(built_server_app_data_record)
    print("[Server] Sent ApplicationData (encrypted)")
    server_app_data_parsed_record = TLS(built_server_app_data_record, tls_session=session)
    server_app_data_parsed_record.show()
    print('\n')
    # ===============================



    conn.close()
    server_sock.close()
    print("[Server] Connection closed")



if __name__ == "__main__":
    run_tls_server()
