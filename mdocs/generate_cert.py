from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

PKEY = {
    'KTY': 'EC2',
    'CURVE': 'P_256',
    'ALG': 'ES256',
    'D': b'\x9cD\xacuq\x9b/\xf2\xea\x17I\x13M\x1c\xe7\x19\x8cA\x82\xc1h{|s\xc8\xb1\x82\x04a\x95*\x01',
    'KID': b"demo-kid"
}

# Your EC private key "D" from PKEY (as bytes)
private_value = int.from_bytes(PKEY['D'], 'big')
private_key = ec.derive_private_key(private_value, ec.SECP256R1())

# Create subject and issuer names (self-signed)
name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'Demo Issuer'),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .sign(private_key, hashes.SHA256())
)

# Write to PEM file
with open("ecdsa_cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
