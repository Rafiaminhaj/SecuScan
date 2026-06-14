from unittest.mock import MagicMock, patch
import pytest
from backend.secuscan.config import settings
from backend.secuscan.notification_service import send_email

@pytest.fixture
def smtp_payload():
    return {
        "finding": {
            "id": "finding-123",
            "task_id": "task-456",
            "plugin_id": "plugin-xyz",
            "title": "Exposed credentials",
            "category": "Credentials",
            "severity": "critical",
            "target": "https://example.com",
            "description": "API key was found exposed in JavaScript code.",
            "remediation": "Revoke the API key and configure it securely on the server side."
        }
    }

@pytest.mark.anyio
@patch("smtplib.SMTP")
async def test_send_email_success(mock_smtp_class, smtp_payload):
    # Set settings variables
    settings.smtp_username = "testuser"
    settings.smtp_password = "testpassword"
    settings.smtp_host = "smtp.test.com"
    settings.smtp_port = 587
    settings.smtp_from_email = "test@secuscan.io"
    settings.smtp_use_tls = True

    # Setup mock SMTP server instance
    mock_server = MagicMock()
    mock_smtp_class.return_value = mock_server
    mock_server.__enter__.return_value = mock_server

    ok, error = await send_email("recipient@target.com", smtp_payload)

    assert ok is True
    assert error is None

    # Verify calls
    mock_smtp_class.assert_called_once_with("smtp.test.com", 587, timeout=10.0)
    mock_server.starttls.assert_called_once()
    mock_server.login.assert_called_once_with("testuser", "testpassword")
    mock_server.sendmail.assert_called_once()


@pytest.mark.anyio
@patch("smtplib.SMTP")
async def test_send_email_disabled_when_no_credentials(mock_smtp_class, smtp_payload):
    # Reset settings variables to None
    settings.smtp_username = None
    settings.smtp_password = None

    ok, error = await send_email("recipient@target.com", smtp_payload)

    # Should skip sending and return True with no error (fallback mode)
    assert ok is True
    assert error is None
    mock_smtp_class.assert_not_called()


@pytest.mark.anyio
@patch("smtplib.SMTP")
async def test_send_email_smtp_failure(mock_smtp_class, smtp_payload):
    settings.smtp_username = "testuser"
    settings.smtp_password = "testpassword"

    # Setup mock SMTP server that raises an exception on login
    mock_server = MagicMock()
    mock_smtp_class.return_value = mock_server
    mock_server.__enter__.return_value = mock_server
    mock_server.login.side_effect = Exception("SMTP Auth Failed")

    ok, error = await send_email("recipient@target.com", smtp_payload)

    assert ok is False
    assert error == "SMTP Auth Failed"
