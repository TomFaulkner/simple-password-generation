import hashlib
import os
import secrets

import requests


def _gen_pass():
    """generate a secure password
    """
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(f"{dir_path}/words.txt") as f:
        words = [word.strip() for word in f]
        return " ".join(secrets.choice(words) for i in range(6))


def check_pass(raw_password):
    """check password against known common passwords
    True if good password, False if bad

    Uses API found here:
    https://haveibeenpwned.com/API/v2
    """
    hash = hashlib.sha1(raw_password.encode()).hexdigest()
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{hash[:5]}")
    if resp.ok and resp.text:
        hashes = [x.split(":")[0] for x in resp.text.split("\r\n")]
        if hash.upper()[5:] in hashes:
            return False
        return True
    raise ConnectionError("Communication Error to HaveIBeenPwned")


def create_password():
    """Create and check a secure password
    Raises ValueError if unable to generate a secure password after 5 attempts
    Raises ConnectionError if unable to reach HaveIBeenPwned.
    """
    for _ in range(5):
        pwd = _gen_pass()
        if check_pass(pwd):
            return pwd
    else:
        raise ValueError("Unable to generate a secure password.")


if __name__ == "__main__":
    print(create_password())
