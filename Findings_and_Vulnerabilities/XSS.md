10. Cross-Site Scripting (XSS)

Module: XSS (DOM, Reflected, Stored)
Difficulty Level: Low
CWE ID: CWE-79 (Improper Neutralization of Input)
CVSS Score: 7.4 (High)
Risk Rating: High

Description:   
    Unsanitized user input rendered in HTML/JS context.
    Impact:Session hijacking, phishing, defacement.

Proof of Concept (PoC):

Step-by-step details:
    Input: <script>alert(1)</script>
    Executed in browser.

Screenshot:F:\Projects\DVWA\Appendices\Screenshots\low_XSS

Mitigation Recommendations:
    
    Escape user input.
    Use CSP headers.
    Sanitize inputs and outputs.