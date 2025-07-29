9. Weak Session IDs
Module: Session Management
Difficulty Level: Low
CWE ID: CWE-330 (Use of Insufficiently Random Values)
CVSS Score: 7.1 (High)
Risk Rating: High

Description:
    Session IDs follow predictable patterns.

Impact:
    Session hijacking, user impersonation.

Proof of Concept (PoC):
Step-by-step details:
    Analyzed session cookies.
    Detected incremental or guessable patterns.

Screenshot:F:\Projects\DVWA\Appendices\Screenshots\low_SessionID

Mitigation Recommendations:
    Use cryptographically secure random session tokens.
    Regenerate session ID after login.
    Set secure and HttpOnly cookie flags.