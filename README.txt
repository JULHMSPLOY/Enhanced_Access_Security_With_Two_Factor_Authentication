Roblox-style Login Demo
=======================

This archive contains two demo Flask applications that simulate Roblox-like login flows for educational demos only.

1) demo_no_mfa: insecure demo (NO MFA, NO rate-limit). Port: 5001
   - Run: python app.py
   - Demo user: roblox_user / password123
   - WARNING: plaintext password in-memory. For demo only.

2) demo_mfa_rate: safer demo (MFA via TOTP + rate-limit). Port: 5002
   - Requires: pyotp, qrcode, flask-limiter, werkzeug
   - pip install flask pyotp qrcode[pil] flask-limiter werkzeug
   - Run: python app.py
   - Usage: login with roblox_user/password123 -> setup MFA (scan QR with Google Authenticator) or verify if already enabled.

IMPORTANT SAFETY NOTE
---------------------
These examples are for learning and demo purposes in a controlled environment only.
Do NOT deploy the insecure app (demo_no_mfa) to the public internet.
Always follow legal and ethical guidelines when demonstrating security concepts.

Files in this archive:
- demo_no_mfa/...
- demo_mfa_rate/...
