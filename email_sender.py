import os
import secrets
import smtplib
import time
from email.mime.text import MIMEText

token_store = {}

SMTP_EMAIL = "docproject098@gmail.com"
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "oahsotfpcaqhpaxx")
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587


def generate_token(user_email):
    token = secrets.token_hex(16)
    expiry = time.time() + 300
    token_store[user_email] = (token, expiry)
    try:
        _send_email(user_email, token)
        print(f"[EMAIL] Token sent to {user_email}")
        return True, token
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False, token


def verify_token(user_email, submitted_token):
    if user_email not in token_store:
        return False, "No token found for this email"
    stored_token, expiry = token_store[user_email]
    if time.time() > expiry:
        del token_store[user_email]
        return False, "Token expired"
    if submitted_token != stored_token:
        return False, "Invalid token"
    del token_store[user_email]
    return True, "Token valid"


def _send_email(to_email, token):
    body = f"""
Your document update authorization token:

    {token}

This token expires in 5 minutes.
Do NOT share this with anyone.
"""
    msg = MIMEText(body)
    msg["Subject"] = "Document Update Token - Action Required"
    msg["From"] = SMTP_EMAIL
    msg["To"] = to_email
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.ehlo()
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.send_message(msg)
