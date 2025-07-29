5. File Upload

Module: File Upload
Difficulty Level: Low
CWE ID: CWE-434 (Unrestricted Upload of File with Dangerous Type)
CVSS Score: 8.8 (High)
Risk Rating: High

Description:
    The application allows upload of .php files without proper validation.

Impact:
    Remote code execution and shell upload.

Proof of Concept (PoC):

Step-by-step details:

    Uploaded shell.php.
    Accessed shell and executed commands.

Screenshot:F:\Projects\DVWA\Appendices\Screenshots\low_FileUpload

Mitigation Recommendations:
    Validate file types and extensions.
    Store uploads outside webroot.
    Rename files and restrict execution.