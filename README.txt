# 2FA Login Demo

## This project contains two demo Flask applications that simulate login flows for educational only.

**1) demo_no_mfa: insecure demo (NO MFA, NO rate-limit).**
   - Run: python app.py
   - Demo user: user / 123456789
   - WARNING: plaintext password in-memory. For demo only.

**2) demo_mfa_rate: safer demo (MFA via TOTP + rate-limit).**
   - Requires: pyotp, qrcode, flask-limiter, werkzeug
   - pip install flask pyotp qrcode[pil] flask-limiter werkzeug
   - Run: python app.py
   - Usage: login with user/123456789 -> setup 2FA (scan QR with Authenticator) or verify if already enabled.

### IMPORTANT SAFETY NOTE
---------------------
These examples are for learning and demo purposes in a controlled environment only.
Do NOT deploy the insecure app (demo_no_mfa) to the public internet.
Always follow legal and ethical guidelines when demonstrating security concepts.
