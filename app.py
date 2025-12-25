import tkinter as tk
from scapy.layers.tls.crypto.suites import *
from tkinter import ttk
from crypto_helpers import get_ECDSA_keys_certificate, get_RSA_keys_certificate
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


class MainApp(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("Multi-Page Tkinter App")
        self.geometry("1000x1000")

        # Container to hold all pages
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.session = None
        self.socket = None

        self.show_frame(
            StartPage(container, self)
        )

    def show_frame(self, frame):
        self.current_frame = frame
        self.current_frame.grid(row=0, column=0, sticky="nsew")
        self.current_frame.tkraise()
        self.update_idletasks()


class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.grid(row=0, column=0, sticky="nsew")
        self.configure(bg="#ffffff")

        label = tk.Label(self, text="Which TLS Role?")
        label.pack(side="top", anchor="center", pady=(20, 50))
        
        def server_setup():
            controller.session = tlsSession(connection_end="server")

            try:
                c = get_ECDSA_keys_certificate("server")
                controller.session.server_certs = [Cert(c["cert"])]
                controller.session.server_key = PrivKey(c["key"])

            except Exception as e:
                print(f"[Server] Error loading certificate/key: {e}")

            
            controller.show_frame(
                ServerWaiting(parent, controller)
            )
            controller.current_frame.wait()

        server = tk.Button(self, text="Server",
                         command=server_setup)
        server.pack(pady=10)


        def client_setup():
            controller.session = tlsSession(connection_end="server")

            try:
                c = get_ECDSA_keys_certificate("client")
                controller.session.client_certs = [Cert(c["cert"])]
                controller.session.client_key = PrivKey(c["key"])

            except Exception as e:
                print(f"[Client] Error loading certificate/key: {e}")


            controller.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            controller.socket.connect((SERVER_IP, SERVER_PORT))
            controller.session.sock = controller.socket

            controller.show_frame(
                ClientHello(parent, controller)
            )

        client = tk.Button(self, text="Client",
                         command=client_setup)
        client.pack(pady=10)


class ServerWaiting(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#ffffff")
        self.controller = controller

        label = tk.Label(self, text="Server waiting for connection...")
        label.pack(side="top", anchor="center", pady=(20, 50))

        bottom_line_frame = ttk.Frame(self)
        bottom_line_frame.pack(side="bottom", anchor="center", pady=(50, 15))
        

    def wait(self):
        self.controller.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.controller.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.controller.socket.bind((SERVER_IP, SERVER_PORT))
        self.controller.socket.listen(1)
        conn, addr = self.controller.socket.accept()
        self.controller.session.sock = conn
        self.controller.socket = conn

        try:
            raw_data = _read_single_TLS_package(self.controller.socket)
        except:
            exit()
        decrypted_data = TLS(raw_data, tls_session=self.controller.session)
        encrypted_data = TLS(raw_data)

        self.controller.show_frame(
            RecievedPackage(
                self.master, self.controller,
                enc_data=encrypted_data.show(dump=True),
                dec_data=decrypted_data.show(dump=True),
                next_frame=ServerHello,
                wait_for_response=0
            )
        )



class ServerHello(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#ffffff")

        def exit():
            controller.socket.close()
            self.session = None
            self.socket = None
            controller.show_frame(
                StartPage(parent, self)
            )

        label = tk.Label(self, text="ServerHello setup")
        label.pack(side="top", anchor="center", pady=(20, 50))

        check_vars = []

        ciphersuites = [
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        ]

        for item in ciphersuites:
            var = tk.IntVar(value=0)  # 0 = unchecked, 1 = checked
            check = tk.Checkbutton(self, text=item.__name__, variable=var, anchor="w")
            check.pack(anchor="w", pady=5)  # Left-aligned, small spacing
            check_vars.append(var)


        def next():
            cs_codes = [ciphersuites[i].val for i in range(len(ciphersuites)) if check_vars[i].get() == 1]

            server_hello = TLSServerHello(
                version=0x0303,  # TLS 1.2
                gmt_unix_time=int(time.time()),
                random_bytes=os.urandom(28),
                sid=os.urandom(32),
                cipher=cs_codes,
                tls_session=controller.session
            )

            server_hello_record = TLS(
                type=22, 
                version=0x0303,
                msg=[server_hello],
                tls_session=controller.session
            )

            # TODO wtf?
            server_random = server_hello.gmt_unix_time.to_bytes(4, 'big') + server_hello.random_bytes
            controller.session.server_random = server_random

            built_server_hello_record = bytes(server_hello_record)
            
            try:
                controller.socket.sendall(built_server_hello_record)
            except:
                exit()

            server_hello_parsed_record = TLS(built_server_hello_record, tls_session=controller.session)
            server_hello_raw_record = TLS(built_server_hello_record)

            controller.show_frame(
                SentPackage(
                    parent, controller,
                    dec_data=server_hello_parsed_record.show(dump=True),
                    enc_data=server_hello_raw_record.show(dump=True),
                    next_frame=ServerCertificate,
                    wait_for_response=0
                )
            )

        bottom_line_frame = ttk.Frame(self)
        bottom_line_frame.pack(side="bottom", anchor="center", pady=(50, 15))

        next_button = tk.Button(bottom_line_frame, text="Send",
                                command=next)
        next_button.grid(row=0, column=1, padx=15, pady=5)

        exit_button = tk.Button(bottom_line_frame, text="Exit",
                                command=exit)
        exit_button.grid(row=0, column=0, padx=15, pady=5)


class ServerCertificate(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#ffffff")

        def exit():
            controller.socket.close()
            self.session = None
            self.socket = None
            controller.show_frame(
                StartPage(parent, self)
            )

        label = tk.Label(self, text="ServerHello setup")
        label.pack(side="top", anchor="center", pady=(20, 50))

        check_vars = []

        ciphersuites = [
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        ]

        for item in ciphersuites:
            var = tk.IntVar(value=0)  # 0 = unchecked, 1 = checked
            check = tk.Checkbutton(self, text=item.__name__, variable=var, anchor="w")
            check.pack(anchor="w", pady=5)  # Left-aligned, small spacing
            check_vars.append(var)

        def next():
            cs_codes = [ciphersuites[i].val for i in range(len(ciphersuites)) if check_vars[i].get() == 1]

            server_hello = TLSServerHello(
                version=0x0303,  # TLS 1.2
                gmt_unix_time=int(time.time()),
                random_bytes=os.urandom(28),
                sid=os.urandom(32),
                cipher=cs_codes,
                tls_session=controller.session
            )

            server_hello_record = TLS(
                type=22, 
                version=0x0303,
                msg=[server_hello],
                tls_session=controller.session
            )

            # TODO wtf?
            server_random = server_hello.gmt_unix_time.to_bytes(4, 'big') + server_hello.random_bytes
            controller.session.server_random = server_random

            built_server_hello_record = bytes(server_hello_record)
            
            try:
                controller.socket.sendall(built_server_hello_record)
            except:
                exit()

            server_hello_parsed_record = TLS(built_server_hello_record, tls_session=controller.session)
            server_hello_raw_record = TLS(built_server_hello_record)

            controller.show_frame(
                SentPackage(
                    parent, controller,
                    dec_data=server_hello_parsed_record.show(dump=True),
                    enc_data=server_hello_raw_record.show(dump=True),
                    next_frame=ServerCertificate,
                    wait_for_response=0
                )
            )

        bottom_line_frame = ttk.Frame(self)
        bottom_line_frame.pack(side="bottom", anchor="center", pady=(50, 15))


        next_button = tk.Button(bottom_line_frame, text="Send",
                                command=next)
        next_button.grid(row=0, column=1, padx=15, pady=5, anchor="e")

        exit_button = tk.Button(bottom_line_frame, text="Exit",
                                command=exit)
        exit_button.grid(row=0, column=0, padx=15, pady=5, anchor="w")



class ClientHello(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#ffffff")

        def exit():
            controller.socket.close()
            self.session = None
            self.socket = None
            controller.show_frame(
                StartPage(parent, self)
            )

        label = tk.Label(self, text="ClientHello setup")
        label.pack(side="top", anchor="center", pady=(20, 50))

        check_vars = []

        ciphersuites = [
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        ]

        for item in ciphersuites:
            var = tk.IntVar(value=0)  # 0 = unchecked, 1 = checked
            check = tk.Checkbutton(self, text=item.__name__, variable=var, anchor="w")
            check.pack(anchor="w", pady=5)  # Left-aligned, small spacing
            check_vars.append(var)

        def next():
            cs_codes = [ciphersuites[i].val for i in range(len(ciphersuites)) if check_vars[i].get() == 1]

            client_hello = TLSClientHello(
                version=0x0303,  # TLS 1.2
                gmt_unix_time=int(time.time()),
                random_bytes=os.urandom(28),
                sid=b'',
                ciphers=cs_codes,
                comp=[0],
                ext=[],
                tls_session=controller.session
            )
            
            client_hello_record = TLS(
                type=22,
                version=0x0303,  
                msg=[client_hello],
                tls_session=controller.session
            )
            

            # TODO wtf?
            client_random = client_hello.gmt_unix_time.to_bytes(4, 'big') + client_hello.random_bytes
            controller.session.client_random = client_random

            built_client_hello_record = bytes(client_hello_record)
            try:
                controller.socket.sendall(built_client_hello_record)
            except:
                exit()

            client_hello_parsed_record = TLS(built_client_hello_record, tls_session=controller.session)
            client_hello_raw_record = TLS(built_client_hello_record)

            controller.show_frame(
                SentPackage(
                    parent, controller,
                    dec_data=client_hello_parsed_record.show(dump=True),
                    enc_data=client_hello_raw_record.show(dump=True),
                    next_frame=ClientKeyExchange,
                    wait_for_response=4
                )
            )
            
        bottom_line_frame = ttk.Frame(self)
        bottom_line_frame.pack(side="bottom", anchor="center", pady=(50, 15))

        next_button = tk.Button(bottom_line_frame, text="Send",
                                command=next)
        next_button.grid(row=0, column=1, padx=15, pady=5)

        exit_button = tk.Button(bottom_line_frame, text="Exit",
                                command=exit)
        exit_button.grid(row=0, column=0, padx=15, pady=5)



class ClientKeyExchange(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#ffffff")

        def exit():
            controller.socket.close()
            self.session = None
            self.socket = None
            controller.show_frame(
                StartPage(parent, self)
            )

        label = tk.Label(self, text="ClientHello setup")
        label.pack(side="top", anchor="center", pady=(20, 50))

        check_vars = []

        ciphersuites = [
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        ]

        for item in ciphersuites:
            var = tk.IntVar(value=0)  # 0 = unchecked, 1 = checked
            check = tk.Checkbutton(self, text=item.__name__, variable=var, anchor="w")
            check.pack(anchor="w", pady=5)  # Left-aligned, small spacing
            check_vars.append(var)

        def next():
            cs_codes = [ciphersuites[i].val for i in range(len(ciphersuites)) if check_vars[i].get() == 1]

            client_hello = TLSClientHello(
                version=0x0303,  # TLS 1.2
                gmt_unix_time=int(time.time()),
                random_bytes=os.urandom(28),
                sid=b'',
                ciphers=cs_codes,
                comp=[0],
                ext=[],
                tls_session=controller.session
            )
            
            client_hello_record = TLS(
                type=22,
                version=0x0303,  
                msg=[client_hello],
                tls_session=controller.session
            )
            

            # TODO wtf?
            client_random = client_hello.gmt_unix_time.to_bytes(4, 'big') + client_hello.random_bytes
            controller.session.client_random = client_random

            built_client_hello_record = bytes(client_hello_record)
            try:
                controller.socket.sendall(built_client_hello_record)
            except:
                exit()

            client_hello_parsed_record = TLS(built_client_hello_record, tls_session=controller.session)
            client_hello_raw_record = TLS(built_client_hello_record)

            controller.show_frame(
                SentPackage(
                    parent, controller,
                    dec_data=client_hello_parsed_record.show(dump=True),
                    enc_data=client_hello_raw_record.show(dump=True),
                    next_frame=ClientKeyExchange,
                    wait_for_response=4
                )
            )
            
        bottom_line_frame = ttk.Frame(self)
        bottom_line_frame.pack(side="bottom", anchor="center", pady=(50, 15))

        next_button = tk.Button(bottom_line_frame, text="Send",
                                command=next)
        next_button.grid(row=0, column=1, padx=15, pady=5, anchor="e")

        exit_button = tk.Button(bottom_line_frame, text="Exit",
                                command=exit)
        exit_button.grid(row=0, column=0, padx=15, pady=5, anchor="w")



class RecievedPackage(tk.Frame):
    def __init__(self, parent, controller, enc_data, dec_data, next_frame, wait_for_response=0):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#ffffff")
        self.controller = controller

        def exit():
            self.controller.socket.close()
            self.session = None
            self.socket = None
            self.controller.show_frame(
                StartPage(parent, self)
            )



        label = tk.Label(self, text="Recieved package:", font=("Helvetica", 16, "bold"))
        label.pack(pady=50)


        package_frame = ttk.Frame(self)
        package_frame.pack(anchor="center", pady=(25, 25))
        
        encrypted_label = tk.Label(package_frame, text="Encrypted:", font=("Helvetica", 14))
        encrypted_label.grid(row=0, column=1, padx=20, pady=5, sticky="w")
        encrypted = tk.Label(package_frame, text=enc_data, wraplength=420, justify="left", font=("Courier", 11))
        encrypted.grid(row=1, column=1, padx=20, pady=5)

        decrypted_label = tk.Label(package_frame, text="Decrypted:", font=("Helvetica", 14))
        decrypted_label.grid(row=0, column=0, padx=20, pady=5, sticky="w")
        decrypted = tk.Label(package_frame, text=dec_data, wraplength=420, justify="left", font=("Courier", 11))
        decrypted.grid(row=1, column=0, padx=20, pady=5)


        bottom_line_frame = ttk.Frame(self)
        bottom_line_frame.pack(side="bottom", anchor="center", pady=(50, 15))

        def next():
            if wait_for_response <= 0:
                self.controller.show_frame(
                    next_frame(parent, controller)
                )
            else:
                try:
                    raw_data = _read_single_TLS_package(self.controller.socket)
                except:
                    exit()
                decrypted_data = TLS(raw_data, tls_session=self.controller.session)
                encrypted_data = TLS(raw_data)

                self.controller.show_frame(
                    RecievedPackage(
                        parent, controller,
                        enc_data=encrypted_data.show(dump=True),
                        dec_data=decrypted_data.show(dump=True),
                        next_frame=next_frame,
                        wait_for_response=wait_for_response-1
                    )
                )

        next_button = tk.Button(bottom_line_frame, text="Next",
                                command=next)
        next_button.grid(row=0, column=1, padx=50, pady=5, sticky='e')

        exit_button = tk.Button(bottom_line_frame, text="Exit",
                                command=exit)
        exit_button.grid(row=0, column=0, padx=50, pady=5, sticky='w')


class SentPackage(tk.Frame):
    def __init__(self, parent, controller, enc_data, dec_data, next_frame, wait_for_response=0):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#ffffff")

        def exit():
            controller.socket.close()
            self.session = None
            self.socket = None
            controller.show_frame(
                StartPage(parent, self)
            )


        label = tk.Label(self, text="Sent package:", font=("Helvetica", 16, "bold"))
        label.pack(pady=50)


        package_frame = ttk.Frame(self)
        package_frame.pack(anchor="center", pady=(25, 25))
        
        encrypted_label = tk.Label(package_frame, text="Encrypted:", font=("Helvetica", 14))
        encrypted_label.grid(row=0, column=1, padx=20, pady=5, sticky="w")
        encrypted = tk.Label(package_frame, text=enc_data, wraplength=420, justify="left", font=("Courier", 11))
        encrypted.grid(row=1, column=1, padx=20, pady=5)

        decrypted_label = tk.Label(package_frame, text="Decrypted:", font=("Helvetica", 14))
        decrypted_label.grid(row=0, column=0, padx=20, pady=5, sticky="w")
        decrypted = tk.Label(package_frame, text=dec_data, wraplength=420, justify="left", font=("Courier", 11))
        decrypted.grid(row=1, column=0, padx=20, pady=5)


        bottom_line_frame = ttk.Frame(self)
        bottom_line_frame.pack(side="bottom", anchor="center", pady=(50, 15))

        def next():
            if wait_for_response <= 0:
                controller.show_frame(
                    next_frame(parent, controller)
                )
            else:
                try:
                    raw_data = _read_single_TLS_package(controller.socket)
                except:
                    exit()
                decrypted_data = TLS(raw_data, tls_session=controller.session)
                encrypted_data = TLS(raw_data)

                controller.show_frame(
                    RecievedPackage(
                        parent, controller,
                        enc_data=encrypted_data.show(dump=True),
                        dec_data=decrypted_data.show(dump=True),
                        next_frame=next_frame,
                        wait_for_response=wait_for_response-1
                    )
                )

        next_button = tk.Button(bottom_line_frame, text="Next",
                                command=next)
        next_button.grid(row=0, column=1, padx=50, pady=5, sticky='e')

        exit_button = tk.Button(bottom_line_frame, text="Exit",
                                command=exit)
        exit_button.grid(row=0, column=0, padx=50, pady=5, sticky='w')

if __name__ == "__main__":
    app = MainApp()
    app.mainloop()