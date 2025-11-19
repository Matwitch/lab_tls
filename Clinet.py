import socket
from network_helpers import _read_single_TLS_package

import time
import os
from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.tls.handshake import *
from scapy.layers.tls.crypto.suites import *
from scapy.layers.tls.session import tlsSession

from cryptography.hazmat.primitives.asymmetric import dh

load_layer("tls")

SERVER_IP = "127.0.0.1"
SERVER_PORT = 4433

def _display_tls_record_safe(record):
    """Display TLS record information without triggering rebuild/signing"""
    print("###[ TLS ]###")
    print(f"  type      = {record.type} ({_tls_content_type_name(record.type)})")
    print(f"  version   = {record.version} ({_tls_version_name(record.version)})")
    print(f"  len       = {record.len}")

    # Display message content without rebuilding
    if record.haslayer(TLSServerKeyExchange):
        ske = record[TLSServerKeyExchange]
        print("  \\msg       \\")
        print("   |###[ TLS Handshake - Server Key Exchange ]###")
        print(f"   |  msgtype   = {ske.msgtype}")
        print(f"   |  msglen    = {ske.msglen}")

        print("   |  \\params    \\")
        print("   |   |###[ Server DH Params ]###")
        if hasattr(ske, 'params') and ske.params:
            params = ske.params
            print(f"   |   |  dh_p      = {len(params.dh_p)} bytes")
            print(f"   |   |  dh_g      = {len(params.dh_g)} bytes")
            print(f"   |   |  dh_Ys     = {len(params.dh_Ys)} bytes")
            if hasattr(params, 'sig_alg'):
                print(f"   |   |  sig_alg   = {params.sig_alg}")
            if hasattr(params, 'sig_len'):
                print(f"   |   |  sig_len   = {params.sig_len}")
        print("   |  sig_val   = <signature present>")
    else:
        print("  msg       = <other message type>")

def _tls_content_type_name(content_type):
    """Convert TLS content type to readable name"""
    types = {
        20: "change_cipher_spec",
        21: "alert",
        22: "handshake",
        23: "application_data",
        24: "heartbeat"
    }
    return types.get(content_type, f"unknown_{content_type}")

def _tls_version_name(version):
    """Convert TLS version to readable name"""
    versions = {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3"
    }
    return versions.get(version, f"unknown_{version:04x}")

def _tls_handshake_type_name(msg_type):
    """Convert TLS handshake type to readable name"""
    types = {
        0: "hello_request",
        1: "client_hello",
        2: "server_hello",
        11: "certificate",
        12: "server_key_exchange",
        13: "certificate_request",
        14: "server_hello_done",
        15: "certificate_verify",
        16: "client_key_exchange",
        20: "finished"
    }
    return types.get(msg_type, f"unknown_{msg_type}")




def run_tls_client():
    # Create TLS session context
    session = tlsSession(connection_end="client")
    
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((SERVER_IP, SERVER_PORT))
    print(f"[Client] Connected to {SERVER_IP}:{SERVER_PORT}")

    from scapy.layers.tls.cert import Cert, PrivKey
    
    try:
        session.client_certs = [Cert("test_server_cert.der")]
        session.client_key = PrivKey("test_server_key.der")
        print("[Server] Test RSA certificate and key loaded successfully")
    except Exception as e:
        print(f"[Server] Error loading test certificate/key: {e}")
        # For demonstration, we'll use dummy cert/key
        print("[Server] Using dummy certificate/key")

    session.pwcs = TLS_DHE_RSA_WITH_AES_128_CBC_SHA256

    # Step 1: Build and send ClientHello
    client_hello = TLSClientHello(
        version=0x0303,  # TLS 1.2
        gmt_unix_time=int(time.time()),
        random_bytes=os.urandom(28),
        sid=b'',
        ciphers=[
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256.val
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
    
    # Manually set client_random in session
    client_random = client_hello.gmt_unix_time.to_bytes(4, 'big') + client_hello.random_bytes
    session.client_random = client_random

    client_sock.sendall(bytes(client_hello_record))
    print("[Client] Sent ClientHello")
    client_hello.show2()
    
    # Update session after sending
    session = client_hello_record.tls_session.mirror()
    
    # Step 2: Receive ServerHello
    data = _read_single_TLS_package(client_sock)
    server_hello_record = TLS(
        data, 
        tls_session=session
    )
    print("[Client] Received ServerHello")
    server_hello_record.show2()
    
    # Session automatically extracts server random and cipher suite
    session = server_hello_record.tls_session
    
    # Step 3: Receive Certificate
    data = _read_single_TLS_package(client_sock)
    cert_record = TLS(
        data, 
        tls_session=session
    )
    print("[Client] Received Certificate")
    cert_record.show2()
    
    # Session automatically extracts server certificate
    session = cert_record.tls_session
    
    # Step 4: Receive ServerKeyExchange (if present)
    data = _read_single_TLS_package(client_sock)
    ske_record = TLS(
        data, 
        tls_session=session
    )
    print("[Client] Received ServerKeyExchange")
    # Custom display function to avoid rebuilding/signing
    # _display_tls_record_safe(ske_record)
    TLS(data).show2()

    # Session automatically extracts server public key
    # Step 5: Receive ServerHelloDone
    session = ske_record.tls_session    
    data = _read_single_TLS_package(client_sock)
    server_done_record = TLS(
        data, 
        tls_session=session
    )
    print("[Client] Received ServerHelloDone")
    server_done_record.show2()
    
    session = server_done_record.tls_session.mirror()
    
    # Step 6: Build and send ClientKeyExchange
    # The server's DH parameters were already extracted when parsing ServerKeyExchange
    # session.server_kx_pubkey now contains the server's public key
    # session.client_kx_ffdh_params should have been set by parsing ServerKeyExchange
    
    # Generate client's DH key pair using the server's parameters
    # First, get the DH parameters from the server's public key
    server_pubkey = session.server_kx_pubkey
    if server_pubkey:
        # Extract parameters from server's public key
        server_params = server_pubkey.parameters()
        # Generate client's private key using these parameters
        client_privkey = server_params.generate_private_key()
        session.client_kx_privkey = client_privkey
        session.client_kx_ffdh_params = server_params
    
    # Now create the ClientKeyExchange with the client's public key
    DHE_params = ClientDiffieHellmanPublic(tls_session=session).fill_missing()
    cke_msg = TLSClientKeyExchange(exchkeys=DHE_params)

    cke_record = TLS(
        type=22,
        version=0x0303,
        msg=[cke_msg],
        tls_session=session
    )

    client_sock.sendall(bytes(cke_record))
    print("[Client] Sent ClientKeyExchange")
    cke_record.show2()

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
    ccs_record.show2()
    
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
    finished_record.show2()
    
    # Don't mirror here - stay in send mode to receive server's messages
    # session = finished_record.tls_session.mirror()
    
    # Step 9: Receive ChangeCipherSpec from server
    data = _read_single_TLS_package(client_sock)
    server_ccs_record = TLS(data, tls_session=session)
    print("[Client] Received ChangeCipherSpec from server")
    server_ccs_record.show2()
    
    # ChangeCipherSpec activates the read cipher, mirror to read mode
    session = server_ccs_record.tls_session.mirror()
    
    # Step 10: Receive Finished from server (encrypted)
    data = _read_single_TLS_package(client_sock)
    print("Client received bytes:", data.hex()[:20])
    server_finished_record = TLS(data, tls_session=session)
    print("[Client] Received Finished from server")
    print("Parsed record type:", server_finished_record.type)
    if server_finished_record.haslayer(TLSFinished):
        print("Contains Finished message")
    else:
        print("Does NOT contain Finished message")
    
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
    app_data_record.show2()
    
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
