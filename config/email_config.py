"""
Email notification configuration for the autonomous cybersecurity agent.
"""

import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# SMTP Configuration
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "security-agent@example.com")
RECIPIENT_EMAILS = os.getenv("RECIPIENT_EMAILS", "").split(",")

# Security Alert Settings
ALERT_LEVELS = {
    "LOW": {"color": "#2ECC71", "prefix": "[LOW RISK]"},
    "MEDIUM": {"color": "#F39C12", "prefix": "[MEDIUM RISK]"},
    "HIGH": {"color": "#E74C3C", "prefix": "[HIGH RISK]"},
    "CRITICAL": {"color": "#C0392B", "prefix": "[CRITICAL RISK]"}
}

def send_email_notification(subject, message, alert_level="MEDIUM"):
    """
    Send email notification with the specified alert level.
    
    Args:
        subject (str): Email subject
        message (str): Email message body
        alert_level (str): Alert level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, RECIPIENT_EMAILS]):
        print("Warning: Email configuration incomplete, notification not sent")
        return False
    
    level_info = ALERT_LEVELS.get(alert_level.upper(), ALERT_LEVELS["MEDIUM"])
    
    # Create message
    email = MIMEMultipart("alternative")
    email["Subject"] = f"{level_info['prefix']} {subject}"
    email["From"] = SENDER_EMAIL
    email["To"] = ", ".join(RECIPIENT_EMAILS)
    
    # Create the HTML message
    html = f"""
    <html>
        <body>
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="background-color: {level_info['color']}; color: white; padding: 10px;">
                    Security Alert: {subject}
                </h2>
                <div style="padding: 15px; border: 1px solid #ddd;">
                    <p>{message}</p>
                    <p>
                        <small>This is an automated message from your Autonomous Cybersecurity Agent.</small>
                    </p>
                </div>
            </div>
        </body>
    </html>
    """
    
    # Attach HTML content
    email.attach(MIMEText(html, "html"))
    
    try:
        # Create secure connection and send email
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(email)
        print(f"Email alert sent: {subject}")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False
