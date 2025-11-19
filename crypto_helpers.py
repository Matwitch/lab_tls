from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import datetime


def _build_x509_certificate(**kwargs):
    builder = x509.CertificateBuilder()
    
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 
        f'{kwargs["subject_name"] if "subject_name" in kwargs else "default_subject_name"}'),
        ]))
    
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 
        f'{kwargs["issuer_name"] if "issuer_name" in kwargs else "default_issuer_name"}'),
        ]))
    
    one_day = datetime.timedelta(1, 0, 0)
    
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(
        datetime.datetime.today() + (one_day * (kwargs["valid_for"] if "valid_for" in kwargs else 30))
        )
    
    builder = builder.serial_number(
        kwargs["serial_number"] if "serial_number" in kwargs else x509.random_serial_number()
        )
    
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
    
    return builder



def generate_RSA_keys_certificate(name: str, key_size: int = 1024):
    private_key = rsa.generate_private_key(65537, key_size)
    
    builder = _build_x509_certificate(
        issuer_name="matvii",
        subject_name="petro",
        valid_for=45
    )
    builder = builder.public_key(private_key.public_key())
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




def generate_ECDSA_keys_certificate(name: str, key_size: int = 1024):
    private_key = ec.generate_private_key(ec.BrainpoolP384R1())
    
    builder = _build_x509_certificate(
        issuer_name="matvii",
        subject_name="petro",
        valid_for=45
    )
    builder = builder.public_key(private_key.public_key())
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