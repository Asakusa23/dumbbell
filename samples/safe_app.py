import os
import secrets
import subprocess

import requests
import yaml
from flask import Flask
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
DEBUG = False
DB_PASSWORD = os.environ["DB_PASSWORD"]


def find_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()


def run_ping(host):
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)


def load_config(data):
    return yaml.safe_load(data)


def hash_password(password):
    return generate_password_hash(password)


def make_token():
    return secrets.token_hex(32)


def fetch(url):
    return requests.get(url, timeout=10)


def read_file(filename):
    base = os.path.realpath("/data")
    target = os.path.realpath(os.path.join(base, filename))
    if not target.startswith(base + os.sep):
        raise ValueError("invalid path")
    with open(target, "r", encoding="utf-8") as handle:
        return handle.read()


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
