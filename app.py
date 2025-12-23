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
        self.geometry("400x300")

        # Container to hold all pages
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.session = None
        self.socket = None

        # Dictionary to store page frames
        self.frames = {}

        self.frames[StartPage.__name__] = StartPage(parent=container, controller=self)
        self.frames[StartPage.__name__].grid(row=0, column=0, sticky="nsew")

        self.frames["Recieved" + StartPage.__name__] = StartPage(parent=container, controller=self)
        self.frames[StartPage.__name__].grid(row=0, column=0, sticky="nsew")

        self.frames[ServerHello.__name__] = StartPage(parent=container, controller=self, next_frame="RecievedPackage")
        self.frames[ServerHello.__name__].grid(row=0, column=0, sticky="nsew")



        self.frames[StartPage.__name__] = StartPage(parent=container, controller=self)
        self.frames[StartPage.__name__].grid(row=0, column=0, sticky="nsew")

        self.frames[StartPage.__name__] = StartPage(parent=container, controller=self)
        self.frames[StartPage.__name__].grid(row=0, column=0, sticky="nsew")


        # Show the starting page
        self.show_frame("StartPage")

    def show_frame(self, page_name):
        """Raise the specified frame to the top"""
        frame = self.frames[page_name]
        frame.tkraise()

class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
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


            controller.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            controller.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            controller.sock.bind((SERVER_IP, SERVER_PORT))
            controller.sock.listen(1)
            
            controller.show_frame("ServerWaiting")
            controller.frames["ServerWaiting"].update(f"[Server] Listening on {SERVER_IP}:{SERVER_PORT}")

        server = tk.Button(self, text="Server",
                         command=server_setup)
        server.pack(pady=10)
        

        btn2 = tk.Button(self, text="Client",
                         command=lambda: controller.show_frame("ClientHello"))
        btn2.pack(pady=10)


class ServerHello(tk.Frame):
    def __init__(self, parent, controller, next_frame):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#ffffff")

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



        bottom_line_frame = ttk.Frame(self)
        bottom_line_frame.pack(side="bottom", anchor="center", pady=(50, 15))

        def next(_data=None):
            controller.show_frame(next_frame)
            controller.frames[next_frame].update(_data)

        def exit():
            controller.show_frame("StartPage")
            # TODO connection close

        next_button = tk.Button(bottom_line_frame, text="Send",
                                command=next)
        next_button.grid(row=0, column=1, padx=15, pady=5, anchor="e")

        exit_button = tk.Button(bottom_line_frame, text="Exit",
                                command=exit)
        exit_button.grid(row=0, column=0, padx=15, pady=5, anchor="w")


class ClientHello(tk.Frame):
    def __init__(self, parent, controller, next_frame):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#ffffff")

        label = tk.Label(self, text="Client Hello Setup")
        label.pack(pady=20)

        btn1 = tk.Button(self, text="Server",
                         command=lambda: controller.show_frame("ServerHello"))
        btn1.pack(pady=10)

        btn2 = tk.Button(self, text="Client",
                         command=lambda: controller.show_frame("ClientHello"))
        btn2.pack(pady=10)

class RecievedPackage(tk.Frame):
    def __init__(self, parent, controller, next_frame):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#ffffff")

        label = tk.Label(self, text="Client Hello Setup")
        label.pack(pady=20)

        self.content = tk.Label(self, text="Client Hello Setup")
        self.content.pack(pady=20)



        btn1 = tk.Button(self, text="Server",
                         command=lambda: controller.show_frame("ServerHello"))
        btn1.pack(pady=10)

        btn2 = tk.Button(self, text="Client",
                         command=lambda: controller.show_frame("ClientHello"))
        btn2.pack(pady=10)


    def update(self, data):
        self.content.config(text=data)


class SentPackage(tk.Frame):
    def __init__(self, parent, controller, next_frame):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#ffffff")

        label = tk.Label(self, text="Client Hello Setup")
        label.pack(pady=20)

        btn1 = tk.Button(self, text="Server",
                         command=lambda: controller.show_frame("ServerHello"))
        btn1.pack(pady=10)

        btn2 = tk.Button(self, text="Client",
                         command=lambda: controller.show_frame("ClientHello"))
        btn2.pack(pady=10)

if __name__ == "__main__":
    app = MainApp()
    app.mainloop()