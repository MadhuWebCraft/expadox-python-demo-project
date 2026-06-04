# Fake AWS Secret (for Gitleaks)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Hardcoded password (Semgrep)
PASSWORD = "admin123"

# SQL Injection example (Semgrep)
def login(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return query

# Insecure command execution (Semgrep)
import os

def run_command(user_input):
    os.system(user_input)
  
import pickle

pickle.loads(b"cos\nsystem\n(S'echo vulnerable'\ntR.")
# VERY STRONG CRITICAL PATTERN
import os
os.system("rm -rf /")
