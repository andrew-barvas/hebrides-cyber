# Annotated test cases for security-config.yaml (run: opengrep test sast-rules/).
import os
import ssl

import httpx
import jwt
import requests
from flask import Flask

app = Flask(__name__)

# ruleid: py-tls-verification-disabled
requests.get("https://partner.example/api", verify=False)

session = requests.Session()
# ruleid: py-tls-verification-disabled
session.verify = False
# ruleid: py-tls-verification-disabled
session.post("https://partner.example/api", json={}, verify=False)
# ruleid: py-tls-verification-disabled
client = httpx.Client(verify=False)
# ok: py-tls-verification-disabled
requests.get("https://partner.example/api", verify="/etc/ssl/private-ca.pem")
# ok: py-tls-verification-disabled
requests.get("https://partner.example/api", timeout=10)

# ruleid: py-ssl-unverified-context
ctx = ssl._create_unverified_context()
good = ssl.create_default_context()
# ruleid: py-ssl-unverified-context
good.verify_mode = ssl.CERT_NONE
# ok: py-ssl-unverified-context
good.verify_mode = ssl.CERT_REQUIRED

# ruleid: py-flask-debug-enabled
app.config["DEBUG"] = True

if os.environ.get("FLASK_DEV"):
    # ok: py-flask-debug-enabled
    app.debug = True

# ok: py-flask-debug-enabled
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG") == "1"

if __name__ == "__main__":
    # ok: py-flask-debug-enabled
    app.run(debug=True)
    # ruleid: py-flask-debug-enabled
    app.run(host="0.0.0.0", port=8000, debug=True)


def read_claims(token, key):
    # ruleid: py-jwt-verification-disabled
    claims = jwt.decode(token, options={"verify_signature": False})
    # ruleid: py-jwt-verification-disabled
    legacy = jwt.decode(token, key, algorithms=["HS256", "none"])
    # ok: py-jwt-verification-disabled
    verified = jwt.decode(token, key, algorithms=["HS256"])
    return claims, legacy, verified
