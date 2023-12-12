from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import json
import requests
import requests.adapters

# Access configuration file
with open ("Client/bin/config/config_est.json", "r") as config:
    # Load configuration as dictionary
    C = json.load(config)

    SERVER_CERT = C["server_cert"]
    SERVER_HOSTNAME = C["server_hostname"]

    CLIENT_CERT = C["client_cert"]
    CLIENT_KEY = C["client_key"]
    CLIENT_KEY_PW = C["client_key_pw"]
    CLIENT_HOSTNAME = C["client_hostname"]
    CLIENT_ALTNAME = C["client_altname"]


def cacerts() -> None:
    # Send Request and receive CA Certificate
    server_cert = requests.get(f"https://{SERVER_HOSTNAME}/.well-known/est/cacerts", verify=False).content.decode('ascii')

    with open(SERVER_CERT, "w") as file:
        file.write(server_cert)


def generate_csr(private_key: rsa.RSAPrivateKey, **kwargs) -> x509.CertificateSigningRequest:
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

    return csr


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


def simpleenroll(csr_obj: x509.CertificateSigningRequest) -> None:

    # Serialize CSR_object
    csr_bytes = csr_obj.public_bytes(serialization.Encoding.PEM)

    # Send CSR and receive Cert
    headers = {'Content-Type': 'application/voucher-cms+json'}
    client_cert = requests.post(
        f"https://{SERVER_HOSTNAME}/.well-known/est/simpleenroll",
        data=csr_bytes,
        headers=headers,
        verify=SERVER_CERT
    ).content.decode('ascii')

    with open(CLIENT_CERT, "w") as file:
        file.write(client_cert)


def main() -> int:

    # Request CA Certificate(s)
    cacerts()

    # Generate Private Key
    client_private_key = generate_private_key(filename=CLIENT_KEY, passphrase=CLIENT_KEY_PW)

    # Generate CSR
    csr_obj = generate_csr(
        private_key=client_private_key,
        hostname=CLIENT_HOSTNAME,
        alt_names=CLIENT_ALTNAME
    )

    # Send CSR and receive Certificate
    simpleenroll(csr_obj=csr_obj)

    return 0


if __name__ == "__main__":
    main()
