# Fake AWS Secret (Gitleaks trigger)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Hardcoded credential (Semgrep SAST)
PASSWORD = "admin123"

# SQL Injection vulnerability (Semgrep SAST)
def login(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return query

# Command injection vulnerability (Semgrep SAST - stronger pattern)
import os

def run_command(user_input):
    os.system(user_input)

# Unsafe deserialization (higher chance of critical finding)
import pickle

def unsafe_load(data):
    return pickle.loads(data)

# Dangerous eval usage (often flagged as HIGH/CRITICAL depending on ruleset)
def execute(code):
    eval(code)

# Extra secret pattern (improves Gitleaks detection confidence)
API_KEY = "1234567890-SECRET-FAKE-KEY-XYZ"
