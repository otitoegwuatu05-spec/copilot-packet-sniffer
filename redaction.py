import re

def mask_ip(ip_address):
    # Masks the last octet of an IP address
    return re.sub(r'\.\d{1,3}$', '.xxx', ip_address)

def redact_sensitive(text):
    # Redacts emails and common sensitive patterns
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[REDACTED_EMAIL]', text)
    text = re.sub(r'(password|token|auth|cookie)=[^&\s]+', r'\1=[REDACTED]', text, flags=re.IGNORECASE)
    return text
if __name__ == "__main__":
    # Test Data
    test_ip = "192.168.1.105"
    test_text = "Login failed for user@email.com with password=Secret123"

    print("--- Redaction Test ---")
    print(f"Original IP:   {test_ip}   -> Masked: {mask_ip(test_ip)}")
    print(f"Original Text: {test_text}")
    print(f"Redacted:      {redact_sensitive(test_text)}")
