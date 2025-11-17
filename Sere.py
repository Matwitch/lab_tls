from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import datetime


private_key = ec.generate_private_key(
    ec.SECP384R1()
)

# 2. Build subject and issuer name (self-signed so they are the same)
builder = x509.CertificateBuilder()

builder = builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, 'cryptography.io'),
]))

builder = builder.issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, 'cryptography.io'),
]))

one_day = datetime.timedelta(1, 0, 0)
builder = builder.not_valid_before(datetime.datetime.today() - one_day)
builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
builder = builder.serial_number(x509.random_serial_number())
builder = builder.public_key(private_key.public_key())

builder = builder.add_extension(
    x509.SubjectAlternativeName(
        [x509.DNSName('cryptography.io')]
    ),
    critical=False
)

builder = builder.add_extension(
    x509.BasicConstraints(ca=False, path_length=None), critical=True,
)

certificate = builder.sign(
    private_key=private_key, algorithm=hashes.SHA256(),
)

# 5. Serialize private key to PEM file (without encryption)
with open("server.key", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# 6. Serialize certificate to PEM file
with open("server.crt", "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))

with open("server.der", "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.DER))

# print("Generated server_key.pem and server_cert.pem")
