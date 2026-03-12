from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

# Load the certificate from a PEM file
with open("ecdsa_cert.pem", "rb") as cert_file:
    cert_data = cert_file.read()

# Parse the certificate
certificate = x509.load_pem_x509_certificate(cert_data)

# Extract the public key
public_key = certificate.public_key()

# Check the type of public key
if isinstance(public_key, ec.EllipticCurvePublicKey):
    print("Elliptic Curve Key")
    print("Curve name:", public_key.curve.name)
elif isinstance(public_key, rsa.RSAPublicKey):
    print("RSA Key")
    print("Key size:", public_key.key_size)
else:
    print("Unsupported key type:", type(public_key))
