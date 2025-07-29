4. File Inclusion

Module: File Inclusion 
Difficulty Level: Low
CWE ID: CWE-98 (Improper Control of File Name or Path)CVSS Score: 7.5 
(High)Risk Rating: High

Description:   
    Unsanitized file input leads to Local File Inclusion (LFI).

Impact:
    Reading sensitive files from the server.

Proof of Concept (PoC):
Step-by-step details:
    Input: ../../../../etc/passwd
    Server responded with file content.

Screenshot:F:\Projects\DVWA\Appendices\Screenshots\low_FileInclusion

Mitigation Recommendations:
    Restrict file paths using whitelisting.
    Use secure coding practices.
    Disable URL file access in configs.