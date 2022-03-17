import hashlib
import os
import secrets
import string

import requests


def _gen_pass():
    """generate a secure password"""
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(f"{dir_path}/words.txt") as f:
        words = [word.strip() for word in f]
        return " ".join(secrets.choice(words) for i in range(6))


def check_havebeenpwned(raw_password):
    """check password against known common passwords
    True if good password, False if bad

    Uses API found here:
    https://haveibeenpwned.com/API/v2
    """
    hash = hashlib.sha1(raw_password.encode()).hexdigest()
    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{hash[:5]}", timeout=0.5
        )
    except requests.exceptions.ConnectionError:
        raise ConnectionError("Communication Error to HaveIBeenPwned")
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
        if check_havebeenpwned(pwd):
            return pwd
    else:
        raise ValueError("Unable to generate a secure password.")


def scoring(
    password,
    *,
    minimum_length=8,
    minimum_score=20,
    points_for_lower=2,
    points_for_upper=2,
    points_for_numbers=2,
    points_per_special=2,
    special_characters=" !@#$%^&*()-=_+.,<>[]{}/?\\|",
    points_per_character=1,
):
    """check password against rules, returns passing: bool and a score.
    This method has the advantage of not requiring stupid rules that cause
    issues for those using a proper password manager, while requiring relatively
    strong passwords.
    """
    score = 0
    passing = len(password) > minimum_length
    if any([char for char in password if char in string.ascii_lowercase]):
        score += points_for_lower
    if any([char for char in password if char in string.ascii_uppercase]):
        score += points_for_upper
    if any([char for char in password if char in string.digits]):
        score += points_for_numbers
    score += (
        len([char for char in password if char in special_characters])
        * points_per_special
    )
    score += len(password) * points_per_character
    if passing:
        passing = score > minimum_score

    return passing, score


if __name__ == "__main__":
    print(create_password())
