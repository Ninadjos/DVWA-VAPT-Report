3. Cross-Site Request Forgery (CSRF)
Module: CSRF
Difficulty Level: Low
CWE ID: CWE-352 (CSRF)
CVSS Score: 6.5 (Medium)
Risk Rating: Medium

Description:
    The CSRF module lacks anti-CSRF tokens allowing attackers to perform actions on behalf of authenticated users.

Impact:
    Sensitive operations can be performed without the user's consent.

Proof of Concept (PoC):

Step-by-step details:

    Captured request to change password.
    Replicated request via crafted HTML form.
    Executed password change when user visited malicious site.

Screenshot:F:\Projects\DVWA\Appendices\Screenshots\low_CSRF

Mitigation Recommendations:
    Use anti-CSRF tokens.
    Validate the origin and referer headers.
    Implement SameSite cookie attributes.