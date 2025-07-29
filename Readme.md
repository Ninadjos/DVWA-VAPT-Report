# DVWA VAPT Assessment

This repository contains a comprehensive VAPT assessment of DVWA, including exploitation steps, risk analysis, and remediation guidelines for each vulnerability.

## 🔍 Vulnerabilities Covered
| Vulnerability                  | Low | Medium | High | Impossible | Notes                              |
| ------------------------------ | --- | ------ | ---- | ---------- | ---------------------------------- |
| Brute-force                    | ✅   | ✅      | ❌    | ❌          | Add screenshots and Intruder setup |
| Command Injection              | ✅   | ✅      | ❌    | ❌          | Include `;id` and `&&` PoCs        |
| CSRF                           | ✅   | ✅      | ❌    | ❌          | Use Burp to capture and re-use     |
| File Inclusion                 | ✅   | ✅      | ❌    | ❌          | Try `../../../../etc/passwd`       |
| File Upload                    | ✅   | ✅      | ❌    | ❌          | Upload `.php` shell                |
| Insecure CAPTCHA               | ✅   | ✅      | ❌    | ❌          | Use browser dev tools to bypass    |
| SQL Injection                  | ✅   | ✅      | ❌    | ❌          | Classic `' or 1=1-- ` tests        |
| Blind SQL Injection            | ✅   | ✅      | ❌    | ❌          | Use time-based payloads            |
| Weak Session IDs               | ✅   | ✅      | ❌    | ❌          | Use session analysis via Burp      |
| XSS (DOM, Reflected, Stored)   | ✅   | ✅      | ❌    | ❌          | `<script>alert(1)</script>`        |
| Content Security Policy Bypass | ✅   | ✅      | ❌    | ❌          | Use inline JS or report-uri bypass |
| JavaScript Exploits            | ✅   | ✅      | ❌    | ❌          | DOM-based flaws                    |
| Open Redirect                  | ✅   | ✅      | ❌    | ❌          | Test with redirect payloads        |


## 📑 Report Files
- [DVWA_VAPT_Report.pdf](./Report/DVWA_VAPT_Report.pdf)
- [Screenshots](./ScreenshotsF:\Projects\DVWA\Appendices\Screenshots/)
- [Findings in Markdown](./FinF:\Projects\DVWA\Findings_and_Vulnerabilities/)

## 🔧 Tools Used
- Burp Suite, Nikto, Hydra, etc.

> This project is for educational and ethical purposes only.
