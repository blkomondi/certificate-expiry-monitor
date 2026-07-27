"""Simple diagnostic script"""
from checker.env import load_dotenv
import os

print("=== Loading .env file ===")
load_dotenv()

print("\n=== Environment Variables ===")
vars_to_check = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USERNAME', 'SMTP_PASSWORD', 'SMTP_FROM', 'ALERT_RECIPIENT']
for var in vars_to_check:
    value = os.environ.get(var, 'NOT SET')
    if var == 'SMTP_PASSWORD' and value != 'NOT SET':
        print(f"{var}: {value[:4]}...{value[-4:]}")
    else:
        print(f"{var}: {value}")

print("\n=== Checking YAML config ===")
try:
    import yaml
    with open('example_config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    email_cfg = config.get('notifications', {}).get('email', {})
    print(f"Email enabled: {email_cfg.get('enabled')}")
    print(f"SMTP host: {email_cfg.get('smtp_host')}")
    print(f"Username: {email_cfg.get('username')}")
except Exception as e:
    print(f"Error reading config: {e}")

print("\n=== Testing SMTP Connection ===")
try:
    import smtplib
    import ssl
    
    host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    port = int(os.environ.get('SMTP_PORT', '587'))
    username = os.environ.get('SMTP_USERNAME')
    password = os.environ.get('SMTP_PASSWORD')
    
    if not username or not password:
        print("ERROR: SMTP_USERNAME or SMTP_PASSWORD not set!")
    else:
        print(f"Connecting to {host}:{port}...")
        context = ssl.create_default_context()
        with smtplib.SMTP(host, port) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            print("STARTTLS OK")
            server.login(username, password)
            print("Login OK!")
            print("\n=== Email should work! ===")
except Exception as e:
    print(f"SMTP Error: {e}")