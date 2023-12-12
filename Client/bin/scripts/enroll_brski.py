import datetime
import os
import secrets
import subprocess
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import requests
import requests.adapters
import json

# Access configuration file
with open("../config/config_brski.json", "r") as config:
    # Load configuration as dictionary
    C = json.load(config)

    IDEVID = C["idevid"]
    IDEVID_KEY = C["idevid_key"]
    IDEVID_KEY_PW = C["idevid_key_pw"]

    # SERIAL_NUMBER = C["serial_number"]

    # Proxy related configurations
    REGISTRAR_CERT = C["registrar_cert"]
    REGISTRAR_HOSTNAME = C["registrar_hostname"]

    MASA_CERT = C["masa_cert"]

    # CSR related configurations
    PLEDGE_CERT = C["pledge_cert"]
    PLEDGE_KEY = C["pledge_key"]
    PLEDGE_KEY_PW = C["pledge_key_pw"]
    PLEDGE_HOSTNAME = C["pledge_hostname"]
    PLEDGE_ALTNAME = C["pledge_altname"]

# Files will be created during Voucher Request and deleted afterwards
# Files are only necessary for OpenSSL-usage
VR_PLEDGE_FILE = "voucher_request.cms"
CMS_FILE = "voucher.cms"


def remove_tempfiles():
    os.remove(VR_PLEDGE_FILE)
    os.remove(CMS_FILE)


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


def generate_voucher_request() -> str:
    # Prepare some parameters for the voucher
    created_on = str(datetime.datetime.now())
    nonce = secrets.token_urlsafe()

    # Extract MASA-URL from IDevID
    idevid = x509.load_pem_x509_certificate(open(IDEVID, "rb").read())
    serial_number = idevid.serial_number

    # Create Voucher Request
    voucher_request = json.dumps(
        {
            "ietf-voucher-request:voucher": {
                "assertion": "proximity",
                "nonce": nonce,
                "serial-number": serial_number,
                "created-on": created_on
                # "proximity-registrar-cert": "base64encodedvalue==" #TODO Certificate des Registrars (erhalten via TLS)
            }
        }
    )

    # Write VR into file to make it accessible for OpenSSL later
    with open(VR_PLEDGE_FILE, "w") as f:
        f.write(voucher_request)

    # TODO Replace hardcoded part of shell-commands

    # Envelope Registrar's VR with a CMS as SignedData
    signed_voucher_request_json = subprocess.run(
        f"openssl cms -sign -signer {IDEVID} -inkey {IDEVID_KEY} -passin pass:{IDEVID_KEY_PW} -nodetach "
        f"-in {VR_PLEDGE_FILE} -outform pem", shell=True, capture_output=True,
        text=True, check=True).stdout

    return signed_voucher_request_json


def request_voucher(signed_voucher_request: str) -> None:
    # HTTPS Connection to Proxy (no verification of Proxy Cert yet)
    headers = {'Content-Type': 'application/voucher-cms+json'}
    response = requests.post(f"https://{REGISTRAR_HOSTNAME}/.well-known/brski/requestvoucher",
                        data=signed_voucher_request,
                        headers=headers,
                        verify=False)

    cms = response.content

    # Write Voucher into file to make it accessible for OpenSSL later
    with open("voucher.cms", "wb") as f:
        f.write(cms)

    # Verify Request-Voucher from Pledge
    voucher_json = subprocess.run(
        f"openssl cms -verify -CAfile {MASA_CERT} -inform pem -in {CMS_FILE}",
        shell=True,
        capture_output=True,
        text=True, check=True).stdout

    # TODO Access Voucher
    voucher_dict = json.loads(voucher_json)  # convert json into dictionary

    # TODO check Serial number

    # TODO check Nonce

    # TODO Verify Registrar Certificate
    # access the certificate within voucher
    registrar_cert = voucher_dict["ietf-voucher:voucher"]["pinned-domain-cert"]

    # Extract content from response, which should be the Voucher in bytes

    # Store the received certificate ( Proxy's cert)

    with open(REGISTRAR_CERT, "w") as certfile:
        certfile.write(registrar_cert)

    remove_tempfiles()


def simpleenroll(csr_obj: x509.CertificateSigningRequest) -> None:
    # Serialize CSR_object
    csr_bytes = csr_obj.public_bytes(serialization.Encoding.PEM)

    headers = {'Content-Type': 'application/voucher-cms+json'}
    response = requests.post(f"https://{REGISTRAR_HOSTNAME}/.well-known/est/simpleenroll", data=csr_bytes,
                             headers=headers,
                             verify=REGISTRAR_CERT)
    # Access the content in response, which should contain the requested certificate

    content = response.content.decode('ascii')

    with open(PLEDGE_CERT, "w") as certfile:
        certfile.write(content)


def main() -> int:
    # Client creates Voucher Request
    signed_voucher_request = generate_voucher_request()
    print("Client created Voucher Request")

    # Send Voucher Request and receive Voucher
    request_voucher(signed_voucher_request)
    print("Client sent Voucher Request and received Voucher")

    # Generate Private Key for CSR
    client_private_key = generate_private_key(PLEDGE_KEY, PLEDGE_KEY_PW)
    print("Client creates Private Key for CSR")

    # Generate CSR
    csr_obj = generate_csr(private_key=client_private_key, hostname=PLEDGE_HOSTNAME, alt_names=PLEDGE_ALTNAME)
    print("Client generates CSR")

    # (5) Send CSR and receives Certificate
    simpleenroll(csr_obj=csr_obj)
    print("Client sent CSR and received Certificate")

    return 0


if __name__ == "__main__":
    main()
