from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import datetime


def generate_RSA_keys_certificate(name: str, key_size: int = 1024):
    private_key = rsa.generate_private_key(65537, key_size)
    
    builder = x509.CertificateBuilder()

    one_day = datetime.timedelta(1, 0, 0)
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(private_key.public_key())

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
    )

    with open(f"{name}.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(f"{name}.crt", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.DER))


# private_key = ec.generate_private_key(
#     ec.SECP384R1()
# )


