import os
import pickle

# =========================
# 🔐 FAKE SECRETS (GITLEAKS)
# =========================
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_KEY = "AKIA_FAKE_KEY_123456"

# =========================
# 🔑 HARDCODED CREDS
# =========================
USERNAME = "admin"
PASSWORD = "admin123"

# =========================
# 💥 SQL INJECTION (SAST)
# =========================
def login(username, password):
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
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
# ⚠️ DANGEROUS DESERIALIZATION
# =========================
def load_data(data):
    return pickle.loads(data)

# =========================
# ⚠️ DANGEROUS DYNAMIC EXEC
# =========================
def execute_code(code):
    exec(code)
