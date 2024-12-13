"""
https.server - SimpleHTTPServer wrapped in TLS"
"""
__version__ = "1.0.1"
__all__ = ["HTTPSServer", "ThreadingHTTPSServer", "generate_cert"]

import os
import ssl
import argparse
import socketserver
import tempfile
import random
from http.server import HTTPServer, SimpleHTTPRequestHandler
from functools import partial
from OpenSSL import crypto, SSL


class HTTPSServer(HTTPServer):
    """
    HTTPServer Class, with its socket wrapped in TLS
    using ssl.wrap_socket
    """

    def __init__(self, cert_path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Wrap Socket using TLS cert
        self.cert_path = cert_path
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert_path)
        self.socket = self.context.wrap_socket(
            self.socket, server_side=True
        )


class ThreadingHTTPSServer(socketserver.ThreadingMixIn, HTTPSServer):
    """
    ThreadedHTTPServer Class, with its socket wrapped in TLS
    using ssl.wrap_socket
    """

    daemon_threads = True


def run_server(bind, port, directory, cert_path):
    """
    Start HTTPSServer. Code based upon code in 'http.server'
    """
    handler_class = partial(SimpleHTTPRequestHandler, directory=directory)
    server_address = (bind, port)
    handler_class.protocol_version = "HTTP/1.0"

    with ThreadingHTTPSServer(cert_path, server_address, handler_class) as httpd:
        sa = httpd.socket.getsockname()
        serve_message = (
            "Serving HTTPS on {host} port {port} (http://{host}:{port}/) ..."
        )
        print(serve_message.format(host=sa[0], port=sa[1]))
        print(f"Using TLS Cert: {cert_path}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received, exiting.")


def generate_cert(cert_path):
    """
    Use OpenSSL to create a new Cert and Key
    """
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "PY"
    cert.get_subject().ST = "Python SimpleHTTPSServer"
    cert.get_subject().OU = "Python SimpleHTTPSServer"
    cert.get_subject().CN = "Python SimpleHTTPSServer"
    # Use a unique serial number
    cert.set_serial_number(random.randint(1, 2147483647))
    cert.gmtime_adj_notBefore(0)
    # Expire cert after 1 year
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, "sha256")

    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode()

    # Write to file if needed
    if cert_path is not None:
        with open(cert_path, "w") as f:
            f.write(key_pem)
            f.write(cert_pem)

    # Return cert and key if required
    return cert_pem, key_pem


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bind",
        "-b",
        default="",
        metavar="ADDRESS",
        help="Specify alternate bind address " "[default: all interfaces]",
    )
    parser.add_argument(
        "--directory",
        "-d",
        default=os.getcwd(),
        help="Specify alternative directory " "[default:current directory]",
    )
    parser.add_argument(
        "port",
        action="store",
        default=8443,
        type=int,
        nargs="?",
        help="Specify alternate port [default: 8000]",
    )
    parser.add_argument(
        "--existing-cert",
        "-e",
        dest="existing_cert",
        help="Specify an existing cert to use "
        "instead of auto-generating one. File must contain "
        "both DER-encoded cert and private key",
    )
    parser.add_argument(
        "--save-cert",
        "-s",
        dest="save_cert",
        action="store_true",
        help="Save certificate file in current directory",
    )
    args = parser.parse_args()

    # If supplied cert use that
    if args.existing_cert is not None:
        cert_path = args.existing_cert
        run_server(args.bind, args.port, args.directory, cert_path)
    # Else generate a cert and key pair and use that
    elif args.save_cert:
        cert_path = os.path.join(os.getcwd(), "cert.pem")
        generate_cert(cert_path)
        run_server(args.bind, args.port, args.directory, cert_path)
    else:
        with tempfile.TemporaryDirectory(prefix="pythonHTTPS_") as tmp_dir:
            cert_path = os.path.join(tmp_dir, "cert.pem")
            generate_cert(cert_path)
            run_server(args.bind, args.port, args.directory, cert_path)


if __name__ == "__main__":
    main()
