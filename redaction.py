import re

def mask_ip(ip):
    """Mask last octet of IPv4 address"""
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".xxx"
    return ip

def redact_sensitive(data):
    """Redact emails, tokens, passwords, cookies, and authorization headers"""
    # Email redaction
    data = re.sub(r'\S+@\S+', '[REDACTED_EMAIL]', data)
    
    # Password or token in query strings
    data = re.sub(r'(password=)[^&\s]+', r'\1[REDACTED]', data)
    data = re.sub(r'(token=)[^&\s]+', r'\1[REDACTED]', data)
    
    # Authorization headers
    data = re.sub(r'Authorization:.*', 'Authorization: [REDACTED_AUTH]', data)
    
    # Cookies
    data = re.sub(r'Cookie:.*', 'Cookie: [REDACTED_COOKIE]', data)
    
    return data
