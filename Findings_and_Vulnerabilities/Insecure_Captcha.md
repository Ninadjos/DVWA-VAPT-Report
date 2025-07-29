6. Insecure CAPTCHA

Module: CAPTCHADifficulty Level: Low
CWE ID: CWE-346 (Origin Validation Error)
CVSS Score: 5.3 (Medium)
Risk Rating: Medium

Description:   
    CAPTCHA can be easily bypassed via browser inspection or automation.

Impact:Automated brute-force attacks.

Proof of Concept (PoC):
Step-by-step details:
    Viewed CAPTCHA answer via page source.
    Submitted correct answer repeatedly.

Screenshot:F:\Projects\DVWA\Appendices\Screenshots\low_InsecureCAPTCHA

Mitigation Recommendations:
    Use dynamic image CAPTCHAs.
    Implement server-side validation.
    Add complexity (timing, distortion).