import os
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import json
import requests
import subprocess
from cryptography.hazmat._oid import ObjectIdentifier

from datetime import datetime
from cryptography import x509
from cryptography.x509 import NameOID

global PRIVATE_KEY
global PRIVATE_KEY_PW

global SERVER_CERT

with open("Proxy/bin/config/config_proxy.json", "r") as config:
    # Load config_brski.json as dictionary
    CONFIG = json.load(config)
    MASA_CERT = CONFIG["masa_cert"]
    PROXY_CERT = CONFIG["proxy_cert"]
    PROXY_KEY = CONFIG["proxy_key"]
    PROXY_KEY_PW = CONFIG["proxy_key_pw"]
    PROXY_HOSTNAME = CONFIG["proxy_hostname"]
    PROXY_PORT = CONFIG["proxy_port"]
    EST_HOSTNAME = CONFIG["est_hostname"]
    EST_PORT = CONFIG["est_port"]
    EST_CERT = CONFIG["est_cert"]


class EST_Server:
    def cacerts():
        return open(PROXY_CERT, "rb").read()


class Registrar():
    # Files will be created during Voucher Request and deleted afterwards
    # Files are only necessary for OpenSSL-usage
    IDEVID_FILE = "idevid.crt"
    VR_PLEDGE_FILE = "vr_pledge.cms"
    VR_REGISTRAR_FILE = "vr_registrar.json"

    def remove_tempfiles(self):
        os.remove(self.IDEVID_FILE)
        os.remove(self.VR_PLEDGE_FILE)
        os.remove(self.VR_REGISTRAR_FILE)

    def cacerts():

        with open(PROXY_CERT, "rb") as f:
            return f.read()

    def extract_voucher_request(self, cms: str):
        # Temporarily write down cms into a file
        # Since in the next steps Openssl needs to access it as a file
        with open(self.VR_PLEDGE_FILE, "w") as f:
            f.write(cms)

        # Verify Request-Voucher from Pledge
        # Extract IdevID into a file idevid.crt
        # Extract Voucher Request (which is in json format)
        voucher_request_json = subprocess.run(
            f"openssl cms -verify -CAfile {MASA_CERT} -inform pem -in {self.VR_PLEDGE_FILE} -signer {self.IDEVID_FILE}",
            shell=True,
            capture_output=True,
            text=True, check=True).stdout

        voucher_request_dict = json.loads(voucher_request_json)  # convert json into dictionary

        return voucher_request_dict

    def verify_voucher_request(self, voucher_request: dict):

        # Check assertion (RFC 8995, 5.2)
        assertion = voucher_request["ietf-voucher-request:voucher"]["assertion"]
        if assertion == "proximity":
            assertion_verified = True

        # TODO check pinned proximity-registrar-cert (RFC 8995, 5.2)
        # Cannot be implemented until unverified TLS Connection is implemented
        # for now default to TRUE
        proximity_verified = True

        ### Verify Serial-number (RFC 8995, 5.5) ###
        # Extract serial-number from IDevID (RFC8995, 5.5)
        with open(self.IDEVID_FILE, "rb") as f:
            idevid_serial_number = x509.load_pem_x509_certificate(f.read()).serial_number

        # Get Serial-number from Pledge's Voucher Request
        vr_serial_number = voucher_request["ietf-voucher-request:voucher"]["serial-number"]

        # Compare both serial-numbers
        if idevid_serial_number == vr_serial_number:
            serial_number_verified = True

        if assertion_verified and proximity_verified and serial_number_verified:
            # Everything is ok
            return True
        else:
            # Something is wrong
            # TODO ERROR Handling
            return False

    def request_voucher(self, voucher_request: dict):
        """
        1. Create Voucher Request
        2. Envelope Voucher Request in CMS as SignedData
        :return:
        """

        vr_pledge = voucher_request

        ### Preparing some parameters for Voucher Request
        # Copy nonce from Pledge'S Voucher Request (RFC8995, 5.5)
        nonce = vr_pledge["ietf-voucher-request:voucher"]["nonce"]
        # Access IDevID
        with open(self.IDEVID_FILE, "rb") as f:
            idevid = x509.load_pem_x509_certificate(f.read())
            # Extract serial-number from IDevID (RFC8995, 5.5)
            serial_number = idevid.serial_number
            # Extract idevid-issuer from IDevID (RFC8995, 5.5)
            idevid_issuer = idevid.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        # Current date and time (RFC8995, 5.5)
        created_on = str(datetime.now())
        # Get Registrar's Cert
        registrar_cert = open(PROXY_CERT, "rb").read().decode()

        # Create Voucher Request
        vr_registrar = json.dumps(
            {
                "ietf-voucher-request:voucher": {
                    "assertion": "proximity",
                    "nonce": nonce,
                    "idevid-issuer": idevid_issuer,
                    "serial-number": serial_number,
                    "created-on": created_on,
                    "prioer-signed-voucher-request": "",  # TODO
                    "registrar-certificates": f"{registrar_cert}"  # TODO PROVISORISCH
                }
            }
        )

        # Write VR into file to make it accessible for OpenSSL later
        open(self.VR_REGISTRAR_FILE, "w").write(vr_registrar)

        # TODO pinned-domain-cert (RFC8995, 5.5)
        # Envelope Registrar's VR with a CMS as SignedData
        cms_vr = subprocess.run(
            f"openssl cms -sign -signer {PROXY_CERT} -inkey {PROXY_KEY} -passin pass:{PROXY_KEY_PW} -nodetach "
            f"-in {self.VR_REGISTRAR_FILE} -outform pem", shell=True, capture_output=True,
            text=True, check=True).stdout

        return cms_vr


class RequestHandler(BaseHTTPRequestHandler):

    def parse_headers(self):

        req_header = {}
        for line in self.headers:
            line_parts = [o.strip() for o in line.split(':', 1)]
            if len(line_parts) == 2:
                req_header[line_parts[0]] = line_parts[1]
        return req_header

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        # print('Response Header')
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding',
                           'content-length', 'Content-Length']:
                # print(key, respheaders[key])
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()

    def do_GET(self):

        # Usually CACERT returns the certificate of the EST Server
        # But since the client only communicates to the Proxy
        # the certificate of the proxy is returned
        if self.path.endswith("/.well-known/est/cacerts"):
            self.send_response(200)
            self.send_header("content_type", "application/pkcs7-mime")
            self.end_headers()

            proxy_cert = EST_Server.cacerts()
            self.wfile.write(proxy_cert)  # encode since string cannot be sent via https requests

    def do_POST(self, body=True):

        if self.path.endswith("/.well-known/brski/requestvoucher"):
            # Get CMS
            content_len = int(self.headers.get('Content-length'))
            cms = self.rfile.read(content_len).decode()

            # Extract Voucher Request from CMS
            voucher_request_dict = Registrar.extract_voucher_request(Registrar(), cms)

            # TODO Verify Voucher Request
            verified = Registrar.verify_voucher_request(Registrar(), voucher_request_dict)

            if verified:

                # Create Voucher Request and envelope in CMS
                cms_vr = Registrar.request_voucher(Registrar(), voucher_request=voucher_request_dict)

                # Extract MASA-URL from IDevID (RFC8995, 5.4)
                idevid = x509.load_pem_x509_certificate(open("idevid.crt", "rb").read())
                hostname_masa = idevid.extensions.get_extension_for_oid(
                    ObjectIdentifier("1.3.6.1.5.5.7.1.32")).value.value.decode()

                # Request Voucher from MASA
                headers = {'Content-Type': 'application/pkcs10'}
                voucher = requests.post(f"https://{hostname_masa}/.well-known/brski/requestvoucher",
                                        data=cms_vr,
                                        headers=headers, verify=MASA_CERT).content

                # Send Voucher to Pledge
                self.send_response(200)
                self.send_header("content_type", "application/voucher-cms+json")
                self.end_headers()
                self.wfile.write(voucher)

                # Clean up temporally files
                Registrar.remove_tempfiles(Registrar())

            else:
                # Send Voucher to Pledge
                self.send_response(401)
                # self.send_header("content_type", "application/voucher-cms+json")
                self.end_headers()
                self.wfile.write(b"Invalid Voucher Request.")

        # EST - SIMPLE ENROLL
        if self.path.endswith("/.well-known/est/simpleenroll"):

            sent = False
            try:
                url = f"https://{EST_HOSTNAME}:{EST_PORT}/.well-known/est/simpleenroll"
                content_len = int(self.headers.get('Content-length'))
                post_body = self.rfile.read(content_len)
                req_header = self.parse_headers()

                resp = requests.post(url, data=post_body, headers=req_header, verify=EST_CERT)
                sent = True

                self.send_response(resp.status_code)
                self.send_resp_headers(resp)
                if body:
                    self.wfile.write(resp.content)
                return
            finally:
                if not sent:
                    self.send_error(404, 'error trying to proxy')


class Proxy:

    def run():
        httpd = HTTPServer((PROXY_HOSTNAME, PROXY_PORT), RequestHandler)
        # httpd.socket = ssl.wrap_socket(httpd.socket,
        #                                keyfile=PROXY_KEY,
        #                                certfile=PROXY_CERT)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=PROXY_CERT, keyfile=PROXY_KEY, password=PROXY_KEY_PW)
        httpd.socket = context.wrap_socket(sock=httpd.socket)
        print("Proxy is running")
        httpd.serve_forever()

        HTTPServer()


if __name__ == "__main__":
    Proxy.run()
