1. Brute-Force Login
Module: Brute Force
Difficulty Level: Low
CWE ID: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
CVSS Score: 8.1 (High)
Risk Rating: High

Description:
The login module accepts unlimited login attempts without rate-limiting or account lockout mechanisms. This allows attackers to brute-force credentials.

Impact:
    Successful brute-force attacks lead to unauthorized access to the application.

Proof of Concept (PoC):

Step-by-step details:
1. Intercepted login request in Burp Suite.
2. Used Burp Intruder with default credential wordlists.
3. Found valid credentials: admin:password

Screenshot:
F:\Projects\DVWA\Appendices\Screenshots\mid_Brute Force

Mitigation Recommendations:

    Use strong password policies.
    Implement account lockout after failed attempts.
    Use CAPTCHA or MFA.