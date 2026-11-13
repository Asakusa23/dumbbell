import hashlib
import logging
import os
import pickle
import random
import ssl
import subprocess
import tarfile
import tempfile

import jwt
import lxml.etree
import requests
import yaml
from flask import Flask, redirect, render_template_string, request

from Crypto.Cipher import AES, DES

app = Flask(__name__)
SECRET_KEY = "dev-secret-key-please-change"
DEBUG = True
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
CSRF_COOKIE_SECURE = False

AWS_ACCESS_KEY_ID = "example-aws-access-key"
AWS_SECRET_ACCESS_KEY = "example-aws-secret-access-key"
DB_PASSWORD = "hunter2"
API_TOKEN = "example-github-token"
SLACK_TOKEN = "example-slack-token"
GOOGLE_API_KEY = "example-google-api-key"
STRIPE_KEY = "example-stripe-key"
DATABASE_URL = "postgresql://admin:supersecret@db.internal:5432/app"
JWT_TOKEN = "example.jwt.token"
AUTH_HEADER = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"
HEADERS = {"x-api-key": "abcdef1234567890"}
INSTALL_CMD = "curl -fsSL http://example.com/install.sh | bash"
PRIVATE_KEY = "example-private-key-material"

AES_KEY = b"0123456789abcdef"
IV = b"1234567890123456"
aes_cipher = AES.new(AES_KEY, AES.MODE_ECB)
des_cipher = DES.new(b"12345678", DES.MODE_ECB)


def find_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def find_user_by_name(cursor, name):
    query = "SELECT * FROM users WHERE name = '%s'" % name
    cursor.execute(query)
    return cursor.fetchone()


def search_items(cursor, term):
    cursor.execute("SELECT * FROM items WHERE name LIKE '%" + term + "%'")
    return cursor.fetchall()


def run_ping(host):
    os.system("ping -c 1 " + host)


def run_backup(path):
    subprocess.run(f"tar -czf /tmp/backup.tar.gz {path}", shell=True)


def calculate(expression):
    return eval(expression)


def load_session(payload):
    return pickle.loads(payload)


def load_config(data):
    return yaml.load(data)


def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def make_token():
    return str(random.random())


def fetch(url):
    return requests.get(f"{url}/api", verify=False)


def fetch_from_request():
    return requests.get(request.args["url"])


def read_file():
    return open(f"/data/{request.args['file']}").read()


def extract(archive):
    tarfile.open(archive).extractall("/tmp/out")


def temp_path():
    return tempfile.mktemp()


def is_admin(user):
    assert user.is_admin


def decode_token(token):
    return jwt.decode(token, options={"verify_signature": False}, verify=False)


def parse_xml(data):
    return lxml.etree.fromstring(data, parser=lxml.etree.XMLParser(resolve_entities=True))


def parse_dom(data):
    import xml.dom.minidom

    return xml.dom.minidom.parseString(data)


def unverified_context():
    return ssl._create_unverified_context()


def go_next():
    return redirect(request.args.get("next"))


def log_login(password):
    logging.info("login password=%s", password)
    print(API_TOKEN)


@app.route("/hello")
def hello():
    return render_template_string(request.args["template"])


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
