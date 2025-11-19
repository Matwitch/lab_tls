from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, ec, dh
from cryptography.hazmat.backends import default_backend
import datetime

from scapy.layers.tls.crypto.pkcs1 import pkcs_i2osp
    

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



def generate_ECDSA_keys_certificate(name: str):
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




def generate_DHE_piece(params: dh.DHParameters | None = None):
    if not params:
        params = dh.generate_parameters(generator=2, key_size=1024)
    
    privkey = params.generate_private_key()

    param_numbers = params.parameter_numbers()
    p_bytes = param_numbers.p.to_bytes((param_numbers.p.bit_length() + 7) // 8, 'big')
    g_bytes = param_numbers.g.to_bytes((param_numbers.g.bit_length() + 7) // 8, 'big')
    
    pubkey = privkey.public_key()
    pubkey_numbers = pubkey.public_numbers()
    y_bytes = pubkey_numbers.y.to_bytes((pubkey_numbers.y.bit_length() + 7) // 8, 'big')

    return p_bytes, g_bytes, y_bytes, privkey
