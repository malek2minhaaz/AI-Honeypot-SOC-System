def analyze_attack(logs):

    logs = logs.lower()

    if "union select" in logs or "' or 1=1" in logs:
        return """
Threat Detected: SQL Injection Attack

Severity: CRITICAL

Recommendations:
- Use prepared SQL statements
- Sanitize user inputs
- Enable Web Application Firewall
- Block suspicious IP addresses
"""

    elif "admin" in logs or "root" in logs:
        return """
Threat Detected: Possible Brute Force Attack

Severity: HIGH

Recommendations:
- Enable MFA
- Use strong passwords
- Enable rate limiting
- Monitor repeated login attempts
"""

    return """
Threat Level: LOW

Recommendations:
- Continue monitoring
- Review logs regularly
"""
