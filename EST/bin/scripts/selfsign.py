from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID, ObjectIdentifier
import json

with open("../config/config.json", "r") as f:
    CONFIG = json.load(f)

    EST_CERT = CONFIG["est_cert"]
    EST_KEY = CONFIG["est_key"]
    EST_KEY_PW = CONFIG["est_key_pw"]
    EST_ALTNAME = CONFIG["est_altname"]
    EST_HOSTNAME = CONFIG["est_hostname"]


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
def generate_certificate(private_key_file: str, key_pw: str, filename: str, **kwargs) -> None:
    with open(private_key_file, "rb") as f:
        server_key = serialization.load_pem_private_key(
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
            x509.NameAttribute(NameOID.COMMON_NAME, kwargs["hostname"])
        ]
    )
    # Because this is self signed, the issuer is always the subject
    issuer = subject
    # This certificate is valid from now until x days
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=999)
    # Used to build the certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=True,
                                             path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=True,
            key_agreement=True,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=True,
            decipher_only=True
        ), critical=False)
        .add_extension(x509.ExtendedKeyUsage(usages=[x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                                                     x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                                                     x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                                                     ObjectIdentifier("1.3.6.1.5.5.7.3.28"),
                                                     x509.oid.ExtendedKeyUsageOID.CODE_SIGNING
                                                     ]),
                       critical=False)
    )
    # Sign the certificate with the private key
    cert = builder.sign(
        server_key, hashes.SHA256(), default_backend()
    )
    # Save Cert to EST Server
    with open(filename, "wb") as certfile:
        certfile.write(cert.public_bytes(serialization.Encoding.PEM))

    # TODO Distribute to Proxy (ONLY FOR TESTING - DELETE LATER)
    with open("../../../Proxy/bin/trusted/est.crt", "wb") as certfile:
        certfile.write(cert.public_bytes(serialization.Encoding.PEM))


# Generate CSR
# def generate_csr(private_key_file: str, key_pw, **kwargs) -> x509.CertificateSigningRequest:
#     with open(private_key_file, "rb") as f:
#         private_key = serialization.load_pem_private_key(
#             f.read(),
#             key_pw.encode("utf-8"),  # getpass().encode("utf-8"),    # asks user to enter pw
#             default_backend()
#         )
#
#     subject = x509.Name(
#         [
#             x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs["country"]),
#             x509.NameAttribute(
#                 NameOID.STATE_OR_PROVINCE_NAME, kwargs["state"]
#             ),
#             x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs["locality"]),
#             x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs["org"]),
#             x509.NameAttribute(NameOID.COMMON_NAME, kwargs["hostname"]),
#         ]
#     )
#
#     # Set up alternate DNS names, which will be valid for the certificate
#     alt_names = []
#     for name in kwargs.get("alt_names", []):
#         alt_names.append(x509.DNSName(name))
#     san = x509.SubjectAlternativeName(alt_names)
#     builder = (
#         x509.CertificateSigningRequestBuilder()
#         .subject_name(subject)
#         .add_extension(san, critical=False)
#     )
#     # Sign CSR with a private key
#     csr = builder.sign(private_key, hashes.SHA256(), default_backend())
#     # Write CSR to disk in PEM format
#     # with open(filename, "wb") as csrfile:
#     #     csrfile.write(csr.public_bytes(serialization.Encoding.PEM))
#     return csr


# def sign_csr(csr, masa_cert_file: str, masa_key_file: str, key_pw: str, masa_url: str, filename: str) -> None:
#     with open(masa_key_file, "rb") as f:
#         private_key = serialization.load_pem_private_key(
#             f.read(),
#             key_pw.encode("utf-8"),  # getpass().encode("utf-8"),    # asks user to enter pw
#             default_backend()
#         )
#
#     with open(masa_cert_file, "rb") as f:
#         # Load CA's Cert
#         public_key = x509.load_pem_x509_certificate(
#             f.read(), default_backend()
#         )
#
#     valid_from = datetime.utcnow()
#     valid_until = valid_from + timedelta(days=30)
#     builder = (
#         x509.CertificateBuilder()
#         # base the subject name on the CSR ...
#         .subject_name(csr.subject)
#         # ... while the issuer is based on the Certificate Authority.
#         .issuer_name(public_key.subject)
#         # gets the public key from the CSR
#         .public_key(csr.public_key())
#         .serial_number(x509.random_serial_number())
#         .not_valid_before(valid_from)
#         .not_valid_after(valid_until)
#         .add_extension(x509.BasicConstraints(ca=True,
#                                              path_length=None), critical=True)
#         # .add_extension(UnrecognizedExtension(ObjectIdentifier("1.3.6.1.5.5.7.1.32"), bytes(f"{masa_url}", "utf-8")), critical = False)
#     )
#
#     # copy any extensions that were set on the CSR
#     for extension in csr.extensions:
#         builder = builder.add_extension(extension.value, extension.critical)
#     # signs the public key with the CA’s private key
#
#     public_key = builder.sign(
#         private_key=private_key,
#         algorithm=hashes.SHA256(),
#         backend=default_backend(),
#     )
#     with open(filename, "wb") as keyfile:
#         keyfile.write(public_key.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    # (0) Load config files
    # (1) Generate new Root Certificate
    # (2) Generate new IDevID

    # ##################################################################################################################
    # (0) Load config files ############################################################################################

    # Load config


        # COUNTRY = CONFIG["country"]
        # STATE = CONFIG["state"]
        # LOCALITY = CONFIG["locality"]
        # ORG = CONFIG["org"]
        # ALT_NAMES = CONFIG["alt_names"]




    # ##################################################################################################################
    # (1) Generate new Root Certificate ################################################################################

    # Generate new Private Key
    private_key = generate_private_key(EST_KEY, EST_KEY_PW)

    # Generate new MASA Certificate
    generate_certificate(
        private_key_file=EST_KEY,
        key_pw=EST_KEY_PW,
        filename=EST_CERT,
        hostname=EST_HOSTNAME,
        alt_names=EST_ALTNAME
    )

    # # ##################################################################################################################
    # # (2) Generate new CA_CERT ##########################################################################################
    #
    # # Generate new Private Key
    # generate_private_key(CA_PRIVATE_KEY, CA_PRIVATE_KEY_PW)
    #
    # csr = generate_csr(
    #     private_key_file=CA_PRIVATE_KEY,
    #     key_pw=CA_PRIVATE_KEY_PW,
    #     country=COUNTRY,
    #     state=STATE,
    #     locality=LOCALITY,
    #     org=ORG,
    #     hostname=HOSTNAME
    # )
    #
    # # Generate new CA_Cert
    # sign_csr(
    #     csr=csr,
    #     masa_cert_file=ROOT_CERT,
    #     masa_key_file=ROOT_PRIVATE_KEY,
    #     masa_url=HOSTNAME,
    #     key_pw=ROOT_PRIVATE_KEY_PW,
    #     filename=CA_CERT
    # )
    #
    # # TODO
    # # () Distribute new Cert to MASA
