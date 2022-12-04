# https.server - Python SimpleHTTPServer over TLS

The Python in-built `http.server` is great when to nead to temperarily
start up a simple webserver, to transfer files or host baisc content.

`https.server` Works exaclty the same, but the connection will be over TLS,
giving slightly more privacy and security.

Just like `http.server`, by default it will server the current directory,
but you can also set it to serve a specific folder.

It can be imported as Class in Python,
or called on the commandline with `python -m https.server` or just `https.server`

Either pass in a pre-generated TLS cert and key, or the project will create a new
tempeory one for you.

## Requirements
https.server runs on Python 3.6 or later

## Install
Easiest way is from pip:
```bash
pip install https.server
```

## Examples
Serve the current folder over TLS on the default port:
```bash
https.server
# OR
python -m https.server
```

Serve a specific folder of TLS
```bash
https.server --directory foo
```

Serve the current folder on 443
**Note:** Usually requires root/administrator privliges
```bash
https.server 443
```

Serve the current folder on localhost only
```bash
https.server --bind 127.0.0.1
```

Save the auto-generated cert for future use:
```bash
https.server --save-cert
```

# Using as a library
You can also use the server as a library to serve cursom HTTP responses:
```python
from http.server import BaseHTTPRequestHandler
from https.server import HTTPSServer, generate_cert

class CustomRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        message = "Hello!"

        self.protocol_version = "HTTP/1.1"
        self.send_response(200)
        self.send_header("Content-Length", len(message))
        self.end_headers()

        self.wfile.write(bytes(message, "utf8"))
        return

cert_path = "cert.pem"
server = ("127.0.0.1", 8443)

generate_cert(cert_path)
httpd = HTTPSServer(cert_path, server, CustomRequestHandler)
httpd.serve_forever()
```

Serve folder over TLS, using an existing certificate
**Note:** Certificate must be DER encoded, and have both the cert
and private key in the same file
```bash
https.server --existing-cert mycert.der
```
