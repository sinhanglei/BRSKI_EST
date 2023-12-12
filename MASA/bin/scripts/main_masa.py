import json
import os
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl


with open("../config/config_masa.json", "rb") as f:
    C = json.load(f)

    MASA_CERT = C["masa_cert"]
    MASA_KEY = C["masa_key"]
    MASA_KEY_PW = C["masa_key_pw"]
    MASA_HOSTNAME = C["masa_hostname"]
    MASA_PORT = C["masa_port"]

    REGISTRAR_CERT = C["registrar_cert"]

    VR_REGISTRAR_FILE = "request_voucher.cms"
    VOUCHER_FILE = "voucher.json"
    PINNED_DOMAIN_FILE = "pinned-domain.crt"


class MASA():

    def remove_tempfiles():
        os.remove(VR_REGISTRAR_FILE)
        os.remove(VOUCHER_FILE)
        os.remove(PINNED_DOMAIN_FILE)

    def extract_voucher_request(self, cms):
        # Temporarily write down cms into a file
        # Since in the next steps Openssl needs to access it as a file
        with open(VR_REGISTRAR_FILE, "w") as f:
            f.write(cms)

        # Verify Request-Voucher from Registrar (RFC8995, 5.5.3)
        # Extract Voucher Request (which is in json format)
        # Extract Pinned-Domain-Certs from CMS (RFC8995, 5.5)
        voucher_request_json = subprocess.run(
            f"openssl cms -verify -CAfile {REGISTRAR_CERT} -inform pem -in {VR_REGISTRAR_FILE} -certsout {PINNED_DOMAIN_FILE}",
            shell=True,
            capture_output=True,
            text=True, check=True).stdout

        voucher_request_dict = json.loads(voucher_request_json)  # convert json into dictionary

        return voucher_request_dict

    def create_voucher(self, voucher_request):
        voucher_request_dict = voucher_request


        # Load pinned-domain-cert (RFC8995, 5.5)
        registrar_cert = open(PINNED_DOMAIN_FILE, "r").read()

        #  Create Voucher RFC8995, 5.6
        nonce = voucher_request_dict["ietf-voucher-request:voucher"]["nonce"]
        serial_number = voucher_request_dict["ietf-voucher-request:voucher"]["serial-number"]
        voucher_json = json.dumps(
            {
                "ietf-voucher:voucher": {
                    "nonce": nonce,
                    "assertion": "verified",
                    "pinned-domain-cert": f"{registrar_cert}",
                    "serial-number": serial_number
                }
            }
        )

        # Write Voucher into file to make it accessible for OpenSSL later
        with open(VOUCHER_FILE, "wb") as f:
            f.write(voucher_json.encode())

        # Envelope Voucher with a CMS as SignedData
        signed_voucher_json = subprocess.run(
            f"openssl cms -sign -signer {MASA_CERT} -inkey {MASA_KEY} -passin pass:{MASA_KEY_PW} -nodetach "
            f"-in {VOUCHER_FILE} -outform pem", shell=True, capture_output=True,
            text=True, check=True).stdout

        return signed_voucher_json


class RequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path.endswith("/.well-known/brski/requestvoucher"):
            self.send_response(200)
            self.send_header("content_type", "application/voucher-cms+json")
            self.end_headers()

            # Access POST-Request data from client
            content_len = int(self.headers.get('Content-length'))
            cms = self.rfile.read(content_len).decode()  # access content, which is cms

            # Extract Voucher Request from CMS
            voucher_request_dict = MASA.extract_voucher_request(MASA(), cms)

            # TODO Does Cert contain id-kp-cmcRA?

            # Create Voucher Request and envelope in CMS
            voucher = MASA.create_voucher(MASA, voucher_request_dict)

            # Send Voucher to Registrar
            self.wfile.write(voucher.encode())

            # Clean up temporally files
            MASA.remove_tempfiles()


class Server:
    def run():
        httpd = HTTPServer((MASA_HOSTNAME, MASA_PORT), RequestHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=MASA_CERT, keyfile=MASA_KEY, password=MASA_KEY_PW)
        httpd.socket = context.wrap_socket(sock = httpd.socket)

        print("Server is running")
        httpd.serve_forever()


if __name__ == "__main__":
    Server.run()
