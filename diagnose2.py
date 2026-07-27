"""Test SMTP with SSL on port 465"""
import smtplib
import ssl
import os

print("Testing SMTP SSL connection (port 465)...")
print()

try:
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=10) as server:
        print("Connected to smtp.gmail.com:465")
        print("Logging in...")
        server.login("blacksaphire.ke@gmail.com", "nhgomxcdclvqcqne")
        print("Login successful!")
        print("\nSending test email...")
        
        from email.mime.text import MIMEText
        msg = MIMEText("Test email from Certificate Monitor!")
        msg['Subject'] = "Test - Certificate Monitor"
        msg['From'] = "blacksaphire.ke@gmail.com"
        msg['To'] = "blacksaphire.ke@gmail.com"
        
        server.send_message(msg)
        print("Email sent! Check your inbox (and spam folder).")
        
except Exception as e:
    print(f"Error: {e}")
    print("\nPossible issues:")
    print("1. Firewall blocking SMTP")
    print("2. Antivirus blocking connection")
    print("3. Network/ISP blocking port 465/587")