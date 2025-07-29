8. Blind SQL Injection

Module: Blind SQLi
Difficulty Level: Low
CWE ID: CWE-89 (SQL Injection)
CVSS Score: 9.0 (Critical)
Risk Rating: Critical

Description:
    SQLi where output is not returned but detectable via timing or logic.

Impact:
    Data extraction and enumeration possible without visible output.

Proof of Concept (PoC):

Step-by-step details:
    Input: ' OR IF(1=1, SLEEP(5), 0)-- 
    Noted delayed response.

Screenshot:F:\Projects\DVWA\Appendices\Screenshots\low_BlindSQLi

Mitigation Recommendations:
 
    Use parameterized queries.
    Monitor for unusual delays.
    Apply input filters.