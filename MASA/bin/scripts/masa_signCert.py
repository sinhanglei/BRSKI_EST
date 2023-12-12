from cryptography.hazmat._oid import ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID, UnrecognizedExtension
import json

with open("MASA/bin/config/config_masa.json", "r") as f:
    C = json.load(f)

    IDEVID_CERT = C["idevid_cert"]
    IDEVID_KEY = C["idevid_key"]
    IDEVID_KEY_PW = C["idevid_key_pw"]
    IDEVID_HOSTNAME = C["idevid_hostname"]
    IDEVID_ALTNAME = C["idevid_altname"]

    MASA_CERT = C["masa_cert"]
    MASA_KEY = C["masa_key"]
    MASA_KEY_PW = C["masa_key_pw"]
    MASA_HOSTNAME = C["masa_hostname"]
    MASA_PORT = C["masa_port"]
    MASA_ALTNAME = C["idevid_altname"]


# Generate private key
def generate_private_key(filename: str, passphrase: str) -> rsa.RSAPrivateKey:
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Set up encryption algorithm to be used on the private key
    utf8_pass = passphrase.encode("utf-8")
    algorithm = serialization.BestAvailableEncryption(utf8_pass)

    # Write private key to disk at specified filename
    # File is encrypted using the password provided
    with open(filename, "wb") as keyfile:
        keyfile.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=algorithm
                # encryption_algorithm=serialization.NoEncryption()
            )
        )
    return private_key


# Generate self-signed certificate
def generate_certificate(private_key_file: str, key_pw: str, filename: str, **kwargs):
    with open(private_key_file, "rb") as f:
        masa_key = serialization.load_pem_private_key(
            f.read(),
            key_pw.encode("utf-8"),  # getpass().encode("utf-8"),    # asks user to enter pw
            default_backend()
        )

    # Collect all Subject Alternative Names in List
    alt_names = []
    for name in kwargs.get("alt_names", []):
        alt_names.append(x509.DNSName(name))
    san = x509.SubjectAlternativeName(alt_names)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, kwargs["hostname"]),
        ]
    )
    # Because this is self signed, the issuer is always the subject
    issuer = subject
    # This certificate is valid from now until 30 days
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=30)
    # Used to build the certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(masa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(x509.BasicConstraints(ca=True,
                                             path_length=None), critical=True)
        .add_extension(san, critical=False)
    )
    # Sign the certificate with the private key
    cert = builder.sign(
        masa_key, hashes.SHA256(), default_backend()
    )

    return cert

    # with open(filename, "wb") as certfile:
    #     certfile.write(cert.public_bytes(serialization.Encoding.PEM))


# Generate CSR
def generate_csr(private_key_file: str, key_pw, **kwargs) -> x509.CertificateSigningRequest:
    with open(private_key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            key_pw.encode("utf-8"),  # getpass().encode("utf-8"),    # asks user to enter pw
            default_backend()
        )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, kwargs["hostname"]),
        ]
    )

    # Set up alternate DNS names, which will be valid for the certificate
    alt_names = []
    for name in kwargs.get("alt_names", []):
        alt_names.append(x509.DNSName(name))
    san = x509.SubjectAlternativeName(alt_names)
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(san, critical=False)
    )
    # Sign CSR with a private key
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    # Write CSR to disk in PEM format
    # with open(filename, "wb") as csrfile:
    #     csrfile.write(csr.public_bytes(serialization.Encoding.PEM))
    return csr


def sign_csr(csr, masa_cert_file: str, masa_key_file: str, key_pw: str, masa_url: str, filename: str):
    with open(masa_key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            key_pw.encode("utf-8"),  # getpass().encode("utf-8"),    # asks user to enter pw
            default_backend()
        )

    with open(masa_cert_file, "rb") as f:
        # Load CA's Cert
        public_key = x509.load_pem_x509_certificate(
            f.read(), default_backend()
        )

    valid_from = datetime.utcnow()
    valid_until = valid_from + timedelta(days=30)
    builder = (
        x509.CertificateBuilder()
        # base the subject name on the CSR ...
        .subject_name(csr.subject)
        # ... while the issuer is based on the Certificate Authority.
        .issuer_name(public_key.subject)
        # gets the public key from the CSR
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
        .add_extension(UnrecognizedExtension(ObjectIdentifier("1.3.6.1.5.5.7.1.32"), bytes(f"{masa_url}", "utf-8")),
                       critical=False)
    )

    # copy any extensions that were set on the CSR
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    # signs the public key with the CA’s private key

    public_key = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    return public_key

    # with open(filename, "wb") as keyfile:
    #     keyfile.write(public_key.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    # Generate Private Key for MASA Certificate
    private_key = generate_private_key(MASA_KEY, MASA_KEY_PW)

    # Generate new MASA Certificate
    cert = generate_certificate(
        private_key_file=MASA_KEY,
        key_pw=MASA_KEY_PW,
        filename=MASA_CERT,
        hostname=MASA_HOSTNAME,
        alt_names=MASA_ALTNAME
    )

    # Save MASA's Cert to MASA
    with open(MASA_CERT, "wb") as certfile:
        certfile.write(cert.public_bytes(serialization.Encoding.PEM))

    # TODO Distribute MASA's Cert to Pledge (FOR TESTING PURPOSE)
    with open("Client/bin/brski_trusted/masa.crt", "wb") as certfile:
        certfile.write(cert.public_bytes(serialization.Encoding.PEM))

    # TODO Distribute MASA's Cert to Proxy (FOR TESTING PURPOSE)
    with open("Proxy/bin/trusted/masa.crt", "wb") as certfile:
        certfile.write(cert.public_bytes(serialization.Encoding.PEM))

    # Generate new Private Key for IDevID
    generate_private_key(IDEVID_KEY, IDEVID_KEY_PW)

    # Generate CSR for IDevID
    csr = generate_csr(
        private_key_file=IDEVID_KEY,
        key_pw=IDEVID_KEY_PW,
        hostname=IDEVID_HOSTNAME,
        alt_names=IDEVID_ALTNAME
    )

    # Generate IDevID and sign with MASA
    idevid = sign_csr(
        csr=csr,
        masa_cert_file=MASA_CERT,
        masa_key_file=MASA_KEY,
        masa_url=f"{MASA_HOSTNAME}:{MASA_PORT}",
        key_pw=MASA_KEY_PW,
        filename=IDEVID_CERT
    )

    # Save IDevID on MASA
    with open(IDEVID_CERT, "wb") as keyfile:
        keyfile.write(idevid.public_bytes(serialization.Encoding.PEM))

    # TODO Distribute IDevID to Pledge (FOR TESTING PURPOSE)
    with open("Client/bin/own_identity/idevid.crt", "wb") as keyfile:
        keyfile.write(idevid.public_bytes(serialization.Encoding.PEM))

    # TODO Distribute IDevID to Pledge (FOR TESTING PURPOSE)
    with open("Client/bin/own_identity/idevid.key", "wb") as keyfile:
        with open("MASA/bin/enrolled/idevid.key") as f:
            keyfile.write(f.read().encode())
