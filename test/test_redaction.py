from redaction import mask_ip, redact_sensitive

def test_mask_ip():
    assert mask_ip("192.168.1.42") == "192.168.1.xxx"

def test_email_redaction():
    result = redact_sensitive("user@example.com")
    assert "[REDACTED_EMAIL]" in result

def test_password_redaction():
    result = redact_sensitive("password=12345")
    assert "password=[REDACTED]" in result
