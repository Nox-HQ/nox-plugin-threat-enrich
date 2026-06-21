import yaml
import hashlib


# Safe: parameterized query — the %s is a DB placeholder, not string formatting.
def get_user(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))


# Safe: authorization CHECK, not a forced admin flag.
def check_permissions(user):
    is_admin = False
    if user.role == "admin":
        return True
    return is_admin


# Safe: empty-string guard, not a hardcoded credential.
def login(request):
    if request.password == "":
        return False
    credentials = ""
    return credentials != ""


# Safe: yaml.load with an explicit safe Loader.
def load_config(raw):
    return yaml.load(raw, Loader=yaml.SafeLoader)


# Safe: strong hash for non-credential data.
def fingerprint(data):
    return hashlib.sha256(data).hexdigest()
