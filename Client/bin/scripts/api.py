from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import os
import json


class RequestHandler(BaseHTTPRequestHandler):


    def do_GET(self):

        # Liefert das erhaltene Zertifikat im PEM-Format zurück.
        # Ist keines vorhanden, wird Code 404 zurückgeliefert.

        if self.path.endswith("api/v0/identity/own"):

            with open("../config/config_brski.json", "r") as config:  # TODO HARDCODE
                # Load configuration as dictionary
                CONFIG = json.load(config)
                IDEVID = CONFIG["brski"]["idevid"]

            if os.path.exists(IDEVID):
                cert = open(IDEVID, "rb").read()
                self.send_response(200)
                self.send_header("content_type", "application/pkcs7-mime")
                self.end_headers()
                self.wfile.write(cert)  # encode since string cannot be sent via https requests
            else:
                self.send_response(404)
                self.send_header("content_type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Fail! Certificate does not exist.")

        if self.path.endswith("api/v0/truststore/est"):

            with open("../config/config_brski.json", "r") as config:  # TODO HARDCODE
                # Load configuration as dictionary
                CONFIG = json.load(config)
                SERVER_CERT = CONFIG["est"]["server_cert"]

            if os.path.exists(SERVER_CERT):
                self.send_response(200)
                self.send_header("content_type", "application/pkcs7-mime")
                self.end_headers()
                with open(SERVER_CERT, "rb") as file:
                    cert = file.read()
                self.wfile.write(cert)
            else:
                self.send_response(404)
                self.send_header("content_type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Fail! Certificate does not exist.")

        if self.path.endswith("api/v0/truststore/brski"):
            with open("../config/config_brski.json", "r") as config:  # TODO HARDCODE
                # Load configuration as dictionary
                CONFIG = json.load(config)
                REGISTRAR_CERT = CONFIG["brski"]["registrar_cert"]

            if os.path.exists(REGISTRAR_CERT):
                self.send_response(200)
                self.send_header("content_type", "application/pkcs7-mime")
                self.end_headers()
                with open(REGISTRAR_CERT, "rb") as file:
                    cert = file.read()
                self.wfile.write(cert)
            else:
                self.send_response(404)
                self.send_header("content_type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Fail! Certificate does not exist.")

        if self.path.endswith("api/v0/config"):

            if os.path.exists("../config/config_brski.json"): # TODO HARDCODE
                self.send_response(200)
                self.send_header("content_type", "application/json")
                self.end_headers()
                with open("../config/config_brski.json", "rb") as file: # TODO HARDCODE
                    config = file.read()
                self.wfile.write(config)
            else:
                self.send_response(404)
                self.send_header("content_type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Fail! Configuration does not exist.")

    def do_POST(self):
        if self.path.endswith("/api/v0/identity/reset"):

            with open("../config/config_brski.json", "r") as config:  # TODO HARDCODE
                # Load configuration as dictionary
                CONFIG = json.load(config)
                CLIENT_CERT = CONFIG["est"]["client_cert"]
                CLIENT_PRIVATE_KEY = CONFIG["est"]["client_private_key"]


            if os.path.exists(CLIENT_CERT):
                os.remove(CLIENT_CERT)
                if os.path.exists(CLIENT_PRIVATE_KEY):
                    os.remove(CLIENT_PRIVATE_KEY)
                self.send_response(200)
                self.send_header("content_type", "text/plain")
                self.end_headers()

                # Send Client MASA's Voucher
                self.wfile.write(b"Success! Identity deleted.")  # encode since string cannot be sent via https requests
            else:
                self.send_response(404)
                self.send_header("content_type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Fail! Identity does not exist.")


class Server:
    def run():

        with open("../config/config_brski.json", "r") as config:          # TODO HARDCODE
            # Load configuration as dictionary
            CONFIG = json.load(config)
            IDEVID = CONFIG["brski"]["idevid"]
            IDEVID_PRIVATE_KEY = CONFIG["brski"]["idevid_private_key"]

        httpd = HTTPServer(("localhost", 4441), RequestHandler)
        httpd.socket = ssl.wrap_socket(httpd.socket,
                                       keyfile=IDEVID_PRIVATE_KEY,
                                       certfile=IDEVID)
        print("Proxy is running")
        httpd.serve_forever()


if __name__ == "__main__":
    Server.run()
