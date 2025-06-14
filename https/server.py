"""
https.server - SimpleHTTPServer wrapped in TLS"
"""
__version__ = "1.0.1"
__all__ = ["HTTPSServer", "ThreadingHTTPSServer", "generate_cert", "extract_client_cert"]

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

    with ThreadingHTTPSServer(cert_path, server_address, handler_class) as httpd:
        sa = httpd.socket.getsockname()
        serve_message = (
            "Serving HTTPS on {host} port {port} (https://{host}:{port}/) ..."
        )
        print(serve_message.format(host=sa[0], port=sa[1]))
        print(f"Using TLS Cert: {cert_path}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received, exiting.")


def generate_cert(cert_path, bind_address="localhost"):
    """
    Use OpenSSL to create a new Cert and Key with proper Subject Alternative Names
    for client verification
    """
    import socket
    
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "Python HTTPS Server"
    cert.get_subject().L = "Local"
    cert.get_subject().O = "Python HTTPS Server"
    cert.get_subject().OU = "Development"
    cert.get_subject().CN = bind_address if bind_address else "localhost"
    
    # Use a unique serial number
    cert.set_serial_number(random.randint(1, 2147483647))
    cert.gmtime_adj_notBefore(0)
    # Expire cert after 1 year
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    
    # Add Subject Alternative Names for proper client verification
    san_list = [
        "DNS:localhost",
        "IP:127.0.0.1",
        "IP:::1",  # IPv6 localhost
    ]
    
    # Add the bind address if it's different from localhost
    if bind_address and bind_address not in ["localhost", "127.0.0.1", ""]:
        # Check if it's an IPv4 address
        try:
            parts = bind_address.split(".")
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                san_list.append(f"IP:{bind_address}")
            else:
                san_list.append(f"DNS:{bind_address}")
        except (ValueError, AttributeError):
            san_list.append(f"DNS:{bind_address}")
    
    # Try to add the actual hostname
    try:
        hostname = socket.gethostname()
        if hostname not in ["localhost"] and f"DNS:{hostname}" not in san_list:
            san_list.append(f"DNS:{hostname}")
    except:
        pass
    
    # Create the SAN extension
    san_extension = crypto.X509Extension(
        b"subjectAltName",
        False,
        ",".join(san_list).encode()
    )
    
    # Add extensions
    cert.add_extensions([
        san_extension,
        crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature,keyEncipherment"),
        crypto.X509Extension(b"extendedKeyUsage", True, b"serverAuth"),
    ])
    
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


def extract_client_cert(cert_path, client_cert_path):
    """
    Extract just the certificate portion (without private key) for client verification
    """
    try:
        with open(cert_path, "r") as f:
            content = f.read()
        
        # Extract only the certificate part
        cert_start = content.find("-----BEGIN CERTIFICATE-----")
        cert_end = content.find("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
        
        if cert_start == -1 or cert_end == -1:
            raise ValueError("Certificate not found in file")
        
        cert_only = content[cert_start:cert_end]
        
        with open(client_cert_path, "w") as f:
            f.write(cert_only)
        
        return cert_only
    except Exception as e:
        raise Exception(f"Failed to extract client certificate: {e}")


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
        "both PEM-encoded cert and private key",
    )
    parser.add_argument(
        "--save-cert",
        "-s",
        dest="save_cert",
        action="store_true",
        help="Save certificate file in current directory",
    )
    parser.add_argument(
        "--client-cert",
        "-c",
        dest="client_cert",
        action="store_true",
        help="Also save a client certificate file (cert only, no private key) for client verification",
    )
    args = parser.parse_args()

    # If supplied cert use that
    if args.existing_cert is not None:
        cert_path = args.existing_cert
        # Extract client cert if requested
        if args.client_cert:
            client_cert_path = os.path.join(os.getcwd(), "client-cert.pem")
            try:
                extract_client_cert(cert_path, client_cert_path)
                print(f"Client certificate saved to: {client_cert_path}")
            except Exception as e:
                print(f"Warning: Could not extract client certificate: {e}")
        run_server(args.bind, args.port, args.directory, cert_path)
    # Else generate a cert and key pair and use that
    elif args.save_cert:
        cert_path = os.path.join(os.getcwd(), "cert.pem")
        bind_addr = args.bind if args.bind else "localhost"
        generate_cert(cert_path, bind_addr)
        print(f"Server certificate saved to: {cert_path}")
        
        # Extract client cert if requested
        if args.client_cert:
            client_cert_path = os.path.join(os.getcwd(), "client-cert.pem")
            try:
                extract_client_cert(cert_path, client_cert_path)
                print(f"Client certificate saved to: {client_cert_path}")
                print(f"\nTo use with requests library:")
                print(f"  import requests")
                print(f"  response = requests.get('https://{bind_addr}:{args.port}', verify='{client_cert_path}')")
            except Exception as e:
                print(f"Warning: Could not extract client certificate: {e}")
        
        run_server(args.bind, args.port, args.directory, cert_path)
    else:
        with tempfile.TemporaryDirectory(prefix="pythonHTTPS_") as tmp_dir:
            cert_path = os.path.join(tmp_dir, "cert.pem")
            bind_addr = args.bind if args.bind else "localhost"
            generate_cert(cert_path, bind_addr)
            run_server(args.bind, args.port, args.directory, cert_path)


if __name__ == "__main__":
    main()
