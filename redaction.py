import re

def mask_ip(ip_address):
    # Masks the last octet of an IP address
    return re.sub(r'\.\d{1,3}$', '.xxx', ip_address)

def redact_sensitive(text):
    # Redacts emails and common sensitive patterns
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[REDACTED_EMAIL]', text)
    text = re.sub(r'(password|token|auth|cookie)=[^&\s]+', r'\1=[REDACTED]', text, flags=re.IGNORECASE)
    return text
