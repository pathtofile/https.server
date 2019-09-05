# Simple HTTPS Server - Python SimpleHTTPServer wrapped in TLS

This project Creates a basic HTTPS Server, that behaves just like
the in-built `http.server` or `SimpleHTTPServer`, but uses TLS.

Just like `http.server`, by default it will server the current directory,
but you can also set it to serve a specific folder.

Just like `SimpleHTTPServer`, it can be imported as Class in Python,
or called on the commandline with `python -m https.server` or just `https.server`

Either pass in a pre-generated TLS cert and key, or the project will create a new
tempeory one for you.

## Example
Serve the current folder over TLS on the default port:
```
https.server
```

Serve a specific folder of TLS
```
https.server --directory foo
```

Serve the current folder on 443
**Note:** Usually requires root/administrator privliges
```
https.server 443
```

Serve the current folder on localhost only
```
https.server --bind 127.0.0.1
```

Serve folder over TLS, using an existing certificate
**Note:** Certificate must be DER encoded, and have both the cert
and private key in the same file
```
https.server --existing-cert mycert.der
```
