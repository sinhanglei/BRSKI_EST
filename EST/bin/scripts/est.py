from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
from cryptography import x509

with open("../config/config.json", "r") as config:
    # Load configuration as dictionary
    CONFIG = json.load(config)
    EST_CERT = CONFIG["est_cert"]
    EST_KEY = CONFIG["est_key"]
    EST_KEY_PW = CONFIG["est_key_pw"]
    CLIENT_CERT = CONFIG["client_cert"]
    EST_HOSTNAME = CONFIG["est_hostname"]
    EST_PORT = CONFIG["est_port"]


class EST:

    def cacerts():
        with open(EST_CERT, "rb") as f:
            return f.read()

    def simpleenroll(csr_file):
        csr = x509.load_pem_x509_csr(csr_file, default_backend())

        # Load CA's Cert
        ca_public_key_file = open(EST_CERT, "rb")
        ca_public_key = x509.load_pem_x509_certificate(
            ca_public_key_file.read(), default_backend()
        )

        # Load CA's Private Key

        ca_private_key_file = open(EST_KEY, "rb")
        ca_private_key = serialization.load_pem_private_key(
            ca_private_key_file.read(),
            EST_KEY_PW.encode("utf-8"),  # getpass().encode("utf-8"),    # asks user to enter pw
            default_backend()
        )

        # Generate Client's certificate
        valid_from = datetime.utcnow()
        valid_until = valid_from + timedelta(days=365)
        builder = (
            x509.CertificateBuilder()
            # base the subject name on the CSR ...
            .subject_name(csr.subject)
            # ... while the issuer is based on the Certificate Authority.
            .issuer_name(ca_public_key.subject)
            # gets the public key from the CSR
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_from)
            .not_valid_after(valid_until)
        )
        # copy any extensions that were set on the CSR
        for extension in csr.extensions:
            builder = builder.add_extension(extension.value, extension.critical)
        # signs the public key with the CA’s private key
        public_key = builder.sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
        with open(CLIENT_CERT, "wb") as keyfile:  # TODO distinguish certificates
            keyfile.write(public_key.public_bytes(serialization.Encoding.PEM))


class RequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path.endswith("/.well-known/est/cacerts"):
            self.send_response(200)
            self.send_header("content_type", "application/pkcs7-mime")
            self.end_headers()

            cacert = EST.cacerts()
            self.wfile.write(cacert)

    def do_POST(self):

        if self.path.endswith("/.well-known/est/simpleenroll"):
            self.send_response(200)
            self.send_header("content_type", "application/pkcs7-mime; smime-type=certs-only")
            self.end_headers()

            # Access POST-Request data from client (CSR)
            content_len = int(self.headers.get('Content-length'))
            # Extract and load CSR
            csr_file = self.rfile.read(content_len)

            EST.simpleenroll(csr_file)

            client_cert = open(CLIENT_CERT, "rb").read()
            self.wfile.write(client_cert)  # encode since string cannot be sent via https requests


class Server:

    def run():
        # TODO config for HTTP-Proxy
        httpd = HTTPServer(server_address=(EST_HOSTNAME, EST_PORT), RequestHandlerClass=RequestHandler)
        # httpd.socket = ssl.wrap_socket(httpd.socket,
        #                                keyfile=EST_KEY,
        #                                certfile=EST_CERT)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=EST_CERT, keyfile=EST_KEY, password=EST_KEY_PW)
        httpd.socket = context.wrap_socket(sock=httpd.socket)
        print("Proxy is running")
        httpd.serve_forever()


if __name__ == "__main__":
    Server.run()
