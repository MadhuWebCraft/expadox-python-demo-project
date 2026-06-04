# Fake AWS Secret (Gitleaks)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Hardcoded credentials (SAST)
USERNAME = "admin"
PASSWORD = "admin123"

# SQL Injection (strong SAST pattern)
def login(username, password):
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    return query

# Command injection (SAST)
import os

def run_command(cmd):
    os.system("bash -c " + cmd)

# Dangerous deserialization (sometimes high severity)
import pickle

def load_data(data):
    return pickle.loads(data)

# Dangerous dynamic execution (high-risk pattern)
def execute_code(code):
    exec(code)
