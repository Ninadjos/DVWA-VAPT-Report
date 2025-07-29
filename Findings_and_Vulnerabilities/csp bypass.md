11. CSP Bypass

Module: CSP
Difficulty Level: Low
CWE ID: CWE-693 (Protection Mechanism Failure)
CVSS Score: 6.1 (Medium)
Risk Rating: Medium

Description:
    Content Security Policy is too lenient and can be bypassed.

Impact:
    Allows XSS or data exfiltration despite policy.

Proof of Concept (PoC):
Step-by-step details:
    Observed wildcard * in CSP header.
    Loaded external script via attacker-controlled domain.

Screenshot:F:\Projects\DVWA\Appendices\Screenshots\low_CSPBypass

Mitigation Recommendations:
    Avoid wildcards in CSP.
    Use strict CSP headers.
    Audit third-party scripts.