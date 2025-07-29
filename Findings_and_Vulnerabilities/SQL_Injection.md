7. SQL Injection

Module: SQLi
Difficulty Level: Low
CWE ID: CWE-89 (SQL Injection)
CVSS Score: 9.8 (Critical)
Risk Rating: Critical

Description:    
    The app concatenates unsanitized user input in SQL queries.

Impact:
    Database compromise, credential dumping, data exfiltration.

Proof of Concept (PoC):
Step-by-step details:
    Input: ' OR 1=1-- 
    Logged in as admin.

Screenshot:F:\Projects\DVWA\Appendices\Screenshots\low_SQLi

Mitigation Recommendations:
    Use parameterized queries (prepared statements).
    Validate input.
    Limit DB permissions.