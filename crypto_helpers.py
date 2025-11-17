from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import datetime




def generate_DHE_private_key():
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    return parameters.generate_private_key()


