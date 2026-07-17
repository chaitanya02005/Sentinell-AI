"""
users/validators.py – Strong password validation for enterprise security.

Password Rules:
  - Minimum 8 characters
  - At least one uppercase letter (A-Z)
  - At least one lowercase letter (a-z)
  - At least one digit (0-9)
  - At least one special character (!@#$%^&*...)
"""

import re


def validate_password_strength(password):
    """
    Validate password against enterprise security rules.
    Returns a list of error messages (empty = valid).
    """
    errors = []

    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")

    if not re.search(r"\d", password):
        errors.append("Password must contain at least one digit.")

    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", password):
        errors.append("Password must contain at least one special character (!@#$%^&*...).")

    return errors
