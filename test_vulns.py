import os
import pickle

# =========================
# 🔐 FAKE SECRETS (GITLEAKS)
# =========================
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_KEY = "AKIA_FAKE_KEY_123456"

GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
DB_PASSWORD = "password123"

# =========================
# 🔑 HARDCODED CREDS
# =========================
USERNAME = "admin"
PASSWORD = "admin123"

# =========================
# 💥 SQL INJECTION (SAST)
# =========================
def login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    return query


def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return query

# =========================
# 💣 COMMAND INJECTION
# =========================
def run_command(cmd):
    os.system("bash -c " + cmd)


def ping_host():
    os.system("ping " + input("host: "))

# =========================
# ⚠️ DESERIALIZATION VULNERABILITY
# =========================
def load_data(data):
    return pickle.loads(data)

# =========================
# ⚠️ DANGEROUS DYNAMIC EXEC
# =========================
def execute_code(code):
    exec(code)

# =========================
# ⚠️ PATH TRAVERSAL STYLE INPUT
# =========================
def read_file(filename):
    with open(filename, "r") as f:
        return f.read()

# =========================
# ⚠️ XSS PAYLOAD (helps DAST context if used in web later)
# =========================
XSS_PAYLOAD = "<script>alert('XSS')</script>"
