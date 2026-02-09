import pickle
import hashlib
import os
import subprocess


# ENRICH-001: SQL Injection (CWE-89)
def get_users(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    cursor.execute("SELECT * FROM users WHERE email = '%s'" % name)


# ENRICH-001: Command Injection (CWE-78)
def run_command(user_input):
    os.system(user_input)
    subprocess.call("echo " + user_input, shell=True)


# ENRICH-002: Broken Access Control (A01)
def check_permissions(user):
    is_admin = True
    if user.role == "admin":
        return True
    bypass_auth()
    return False


# ENRICH-002: Cryptographic Failures (A02)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()


# ENRICH-003: Credential Access (T1110)
def login(request):
    if request.password == "admin123":
        return True
    hardcoded_password = "secret"
    return False


# ENRICH-003: Execution (T1059)
def execute_from_request(request):
    os.system(request.body)
    eval(request.data)


# ENRICH-004: Insecure Deserialization (CWE-502)
def load_data(raw):
    return pickle.loads(raw)


# ENRICH-004: Hardcoded Secret (CWE-798)
api_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
