"""
Unit tests for the email notification system.
"""

import unittest
import os
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from config.email_config import send_email_notification

class TestEmailNotifications(unittest.TestCase):
    """Test cases for the email notification system."""
    
    @patch('config.email_config.smtplib.SMTP')
    def test_send_notification_success(self, mock_smtp):
        """Test successful email notification sending."""
        # Setup mock
        mock_smtp_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_smtp_instance
        
        # Set environment variables for the test
        with patch.dict(os.environ, {
            'SMTP_SERVER': 'smtp.test.com',
            'SMTP_PORT': '587',
            'SMTP_USERNAME': 'test@example.com',
            'SMTP_PASSWORD': 'password123',
            'SENDER_EMAIL': 'security@example.com',
            'RECIPIENT_EMAILS': 'admin@example.com'
        }):
            # Call the function
            result = send_email_notification(
                "Test Alert", 
                "This is a test security alert", 
                "MEDIUM"
            )
            
            # Assertions
            self.assertTrue(result)
            mock_smtp_instance.login.assert_called_once_with("test@example.com", "password123")
            mock_smtp_instance.send_message.assert_called_once()
    
    @patch('config.email_config.smtplib.SMTP')
    def test_send_notification_smtp_error(self, mock_smtp):
        """Test email notification with SMTP error."""
        # Setup mock to raise exception
        mock_smtp.return_value.__enter__.side_effect = Exception("SMTP connection error")
        
        # Set environment variables for the test
        with patch.dict(os.environ, {
            'SMTP_SERVER': 'smtp.test.com',
            'SMTP_PORT': '587',
            'SMTP_USERNAME': 'test@example.com',
            'SMTP_PASSWORD': 'password123',
            'SENDER_EMAIL': 'security@example.com',
            'RECIPIENT_EMAILS': 'admin@example.com'
        }):
            # Call the function
            result = send_email_notification(
                "Test Alert", 
                "This is a test security alert", 
                "MEDIUM"
            )
            
            # Assertions
            self.assertFalse(result)
    
    def test_send_notification_missing_config(self):
        """Test email notification with missing configuration."""
        # Set environment variables for the test (missing some required ones)
        with patch.dict(os.environ, {
            'SMTP_SERVER': 'smtp.test.com',
            # Missing SMTP_PORT
            'SMTP_USERNAME': 'test@example.com',
            # Missing SMTP_PASSWORD
            'SENDER_EMAIL': 'security@example.com',
            'RECIPIENT_EMAILS': 'admin@example.com'
        }):
            # Call the function
            result = send_email_notification(
                "Test Alert", 
                "This is a test security alert", 
                "MEDIUM"
            )
            
            # Assertions
            self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
