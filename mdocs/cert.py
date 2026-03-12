from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta

# Generate EC private key (ECDSA)
private_key = ec.generate_private_key(ec.SECP256R1())  # Also known as P-256

# Certificate subject and issuer (self-signed in this case)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Braga"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Braga"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"IMT Falso")
])

# Build certificate
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(private_key, hashes.SHA256())  # ECDSA with SHA-256
)

# Save private key to PEM
with open("ecdsa_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))

# Save certificate to PEM
with open("ecdsa_cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
