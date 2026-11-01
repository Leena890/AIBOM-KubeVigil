from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS_DIR = Path("certs")
CERTS_DIR.mkdir(exist_ok=True)

# 1. Generate CA Private Key and Certificate
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "kubevigil-ca"),
])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_subject)
    .issuer_name(ca_subject)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)

# 2. Generate Server Private Key and Certificate
server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "kubevigil-webhook.default.svc"),
])

# Subject Alternative Names (SANs) for local and in-cluster resolution
san_entries = [
    x509.DNSName("localhost"),
    x509.DNSName("kubevigil-webhook"),
    x509.DNSName("kubevigil-webhook.default"),
    x509.DNSName("kubevigil-webhook.default.svc"),
    x509.DNSName("kubevigil-webhook.default.svc.cluster.local"),
    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
]

server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_subject)
    .issuer_name(ca_subject)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
    .sign(ca_key, hashes.SHA256())
)

# 3. Save artifacts into certs/
with open(CERTS_DIR / "ca.key", "wb") as f:
    f.write(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

with open(CERTS_DIR / "ca.crt", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

with open(CERTS_DIR / "server.key", "wb") as f:
    f.write(server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

with open(CERTS_DIR / "server.crt", "wb") as f:
    f.write(server_cert.public_bytes(serialization.Encoding.PEM))

print("Certificates successfully generated in the certs/ directory.")
