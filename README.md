# simple-password-generation

Generate and check secure passwords in Python.

This is intended for use as a password strength checking and suggestion library for APIs, though it could also be integrated into a password database application.

# Usage

    >>> from simple_pass import create_password, check_havebeenpwned, scoring
    >>> password = create_password()
    >>> print(password)
    unfurcate necessitate nonfact retrogradation swathband orthitic
    
    >>> check_havebeenpwned(password)
    True
    >>> scoring(password)
    (True, 75)


## HaveIBeenPwned
Generated passwords are automatically securely checked against the [HaveIBeenPwned](https://haveibeenpwned.com) database.
Partial hashes are sent using the HaveIBeenPwned API. This can not be reconstructed to determine the checked password.

User generated passwords can be checked by calling `check_havebeenpwned(password)`.


## Scoring Options
Passwords can be checked with a scoring based system using the following options.

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

I believe this scoring system encourages long and difficult to guess passwords by rewarding lengthy passwords and special characters, but without requiring a specific password format or frustrating rules.

## XKCD, Comics, Horses, and batteries

For wisdom on what makes a good password see the famous [xkcd correct horse battery staple comic](https://xkcd.com/936/). The `correct horse battery staple` example passes with a score of 36 using the default parameters. It does not pass the HaveIBeenPwned check, however, as it is a well known password that has probably been found in many breaches.
