import os
import secrets
import time
import urllib.request
import urllib.error
import json

token_store = {}

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "re_XKTw2VHX_88ferwxzsqdHJJbZSqhAZyMc")
FROM_EMAIL = "onboarding@resend.dev"

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
    payload = json.dumps({
        "from": FROM_EMAIL,
        "to": [to_email],
        "subject": "Document Update Token - Action Required",
        "text": f"Your document update authorization token:\n\n    {token}\n\nThis token expires in 5 minutes.\nDo NOT share this with anyone."
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json"
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        result = json.loads(resp.read())
        print(f"[RESEND] {result}")
