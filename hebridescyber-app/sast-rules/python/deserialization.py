# Annotated test cases for deserialization.yaml (run: opengrep test sast-rules/).
import base64
import json
import pickle

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/session")
def restore_session():
    blob = base64.b64decode(request.cookies.get("session"))
    # ruleid: py-pickle-untrusted
    state = pickle.loads(blob)
    # ok: py-pickle-untrusted
    prefs = json.loads(request.cookies.get("prefs"))
    return str(state) + str(prefs)


@app.route("/upload", methods=["POST"])
def upload_model():
    # ruleid: py-pickle-untrusted
    model = pickle.load(request.files["model"])
    return str(model)


def load_cache():
    # Not request data: produced and stored by the application itself.
    with open("/var/cache/app/state.pkl", "rb") as fh:
        # ok: py-pickle-untrusted
        return pickle.load(fh)


@app.route("/import", methods=["POST"])
def import_config():
    body = request.get_data()
    # ruleid: py-yaml-unsafe-load
    config = yaml.load(body, Loader=yaml.Loader)
    # ruleid: py-yaml-unsafe-load
    other = yaml.unsafe_load(body)
    # ok: py-yaml-unsafe-load
    safe = yaml.safe_load(body)
    # ok: py-yaml-unsafe-load
    also_safe = yaml.load(body, Loader=yaml.SafeLoader)
    return str((config, other, safe, also_safe))
