import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

def send_cem_notification(recipient_email, subject, content):
    """
    Sends an email using SendGrid API via Port 443.
    Bypasses ISP SMTP blocking.
    """
    # REPLACE 'YOUR_SENDGRID_API_KEY' with your actual key starting with SG.
    API_KEY = 'YOUR_SENDGRID_API_KEY_HERE' 
    
    # The 'from_email' MUST be an email you have verified in your SendGrid dashboard
    FROM_EMAIL = 'your-verified-email@example.com' 

    message = Mail(
        from_email=FROM_EMAIL,
        to_emails=recipient_email,
        subject=subject,
        plain_text_content=content
    )

    try:
        sg = SendGridAPIClient(API_KEY)
        response = sg.send(message)
        print(f"Email sent! Status Code: {response.status_code}")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Quick test if you run this file directly
if __name__ == "__main__":
    send_cem_notification("your-personal-email@gmail.com", "CEM Test", "Testing HTTPS mail delivery.")