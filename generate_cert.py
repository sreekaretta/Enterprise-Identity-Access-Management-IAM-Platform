"""
Run this once to generate a self-signed TLS certificate for HTTPS.
Usage: python generate_cert.py

Creates cert.pem and key.pem in the project directory.
The app will automatically use them when they exist.

IMPORTANT: Your browser will show a security warning because the certificate
is self-signed (not issued by a trusted CA). Click 'Advanced' → 'Proceed'.
This is expected for a local development server — in production you would use
a certificate from a trusted CA (Let's Encrypt, DigiCert, etc.).
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import ipaddress


def generate():
    print("Generating self-signed TLS certificate...")

    # Generate a 2048-bit RSA private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Certificate subject and issuer (self-signed = same entity)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,        "IAM Lab"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,  "IAM Lab Development"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,        "US"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write certificate (public)
    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Write private key (keep this secret)
    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print()
    print("Certificate created successfully:")
    print("  cert.pem  — public certificate (valid 365 days)")
    print("  key.pem   — private key")
    print()
    print("Start the app normally with:  python app.py")
    print("Then open:  https://127.0.0.1:5000")
    print()
    print("Browser security warning is expected for self-signed certs.")
    print("Click 'Advanced' -> 'Proceed to 127.0.0.1 (unsafe)' to continue.")


if __name__ == "__main__":
    generate()
