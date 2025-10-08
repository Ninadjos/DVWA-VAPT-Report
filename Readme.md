# DVWA Vulnerability Assessment & Penetration Testing (VAPT) Report 🛡️

This repository documents a full-scale Vulnerability Assessment and Penetration Testing (VAPT) performed against **Damn Vulnerable Web Application (DVWA)**. The purpose of this assessment is to identify, exploit, and document security vulnerabilities across all DVWA modules and difficulty levels, and provide actionable remediation steps.

---

## 📋 Summary

- **Target:** DVWA (Damn Vulnerable Web Application)
- **Scope:** All vulnerability modules across Low, Medium
- **Tools Used:** Burp Suite, OWASP ZAP, Nikto, Hydra, curl, Firefox Dev Tools, etc.
- **Author:** *Ninad Joshi*

---

## 🛠️ Vulnerabilities Covered

| #  | Vulnerability                   | CWE ID  | CVSS  | Risk Level |
|----|--------------------------------|---------|-------|------------|
| 1  | Brute-Force Login              | CWE-307 | 8.1   | High       |
| 2  | Command Injection              | CWE-77  | 9.8   | Critical   |
| 3  | Cross-Site Request Forgery     | CWE-352 | 6.5   | Medium     |
| 4  | File Inclusion (LFI)           | CWE-98  | 7.5   | High       |
| 5  | File Upload                    | CWE-434 | 8.8   | High       |
| 6  | Insecure CAPTCHA               | CWE-346 | 5.3   | Medium     |
| 7  | SQL Injection                  | CWE-89  | 9.8   | Critical   |
| 8  | Blind SQL Injection            | CWE-89  | 9.0   | Critical   |
| 9  | Weak Session IDs               | CWE-330 | 7.1   | High       |
| 10 | Cross-Site Scripting (XSS)     | CWE-79  | 7.4   | High       |
| 11 | CSP Bypass                     | CWE-693 | 6.1   | Medium     |
| 12 | JavaScript Exploits            | CWE-79/94 | 6.5 | Medium     |
| 13 | Open Redirect                  | CWE-601 | 6.1   | Medium     |

---

## 📁 Repository Structure

DVWA-VAPT-Report/
├── README.md                             # Main project README with summary and links
├── Report/                               # Final reports in common formats
│   ├── DVWA_VAPT_Report.docx             # Full professional report (editable)
│   └── DVWA_VAPT_Report.pdf              # Exported version for sharing
├── Screenshots/                          # PoC images per vulnerability
│   ├── BruteForce/
│   ├── CommandInjection/
│   ├── CSRF/
│   ├── FileInclusion/
│   ├── FileUpload/
│   ├── InsecureCAPTCHA/
│   ├── SQLInjection/
│   ├── BlindSQLInjection/
│   ├── WeakSessionIDs/
│   ├── XSS/
│   ├── CSPBypass/
│   ├── JavaScript/
│   └── OpenRedirect/
├── Findings/                             # One Markdown report per vulnerability
│   ├── BruteForce.md
│   ├── CommandInjection.md
│   ├── CSRF.md
│   ├── FileInclusion.md
│   ├── FileUpload.md
│   ├── InsecureCAPTCHA.md
│   ├── SQLInjection.md
│   ├── BlindSQLInjection.md
│   ├── WeakSessionIDs.md
│   ├── XSS.md                            # Combined: Reflected, Stored, DOM
│   ├── CSPBypass.md
│   ├── JavaScript.md
│   └── OpenRedirect.md
├── Appendices/                           # Supporting and technical detail sections
│   ├── Tools_Used.md                     # Nmap, Burp Suite, WFuzz, etc.
│   ├── Environment_Config.md             # DVWA setup, server stack, OS info
│   └── References.md                     # CWE, CVSS, OWASP Top 10 references


---

## 🧪 Methodology

1. **Reconnaissance** – Manual exploration of each module across difficulty levels.
2. **Exploitation** – Vulnerabilities exploited using tools like Burp Suite Intruder, curl, and browser-based payloads.
3. **Documentation** – Each vulnerability documented with:
   - CWE ID and CVSS Score
   - Detailed proof of concept
   - Screenshots of each step
   - Mitigation recommendations

---

## 📸 Screenshots

All screenshots related to the PoCs are stored under the `/F:\Projects\DVWA\Screenshots/` directory and referenced within the main report.

---

## 🛡️ Disclaimers

- This project is intended **only for educational and ethical testing purposes**.
- Never test real systems without **explicit written permission**.

---

## 📬 Contact

For questions, feedback, or collaboration:
- **Author:** Ninad Joshi
- **LinkedIn:** [linkedin.com/in/ninadjoshi](https://www.linkedin.com/in/ninadjoshi)

---

⭐️ Star the repo if you found it useful. Contributions and improvements are welcome!
