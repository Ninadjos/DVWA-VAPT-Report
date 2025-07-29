2.Command Injection
Difficulty Level: Low
CWE ID: CWE-77 (Command Injection)
CVSS Score: 9.8 (Critical)
Risk Rating: Critical

Description:
    The application does not sanitize user input passed to system commands, allowing remote command execution.

Impact:
    Remote code execution on the underlying OS.

Proof of Concept (PoC):
Step-by-step details:

    Accessed the Command Execution module.
    Input: 127.0.0.1; id
    Received system response with UID and GID.

Screenshot:F:\Projects\DVWA\Appendices\Screenshots\low_CommandInjection

Mitigation Recommendations:

    Use parameterized OS commands or avoid them.
    Validate and sanitize user inputs.
    Apply least privilege principles.