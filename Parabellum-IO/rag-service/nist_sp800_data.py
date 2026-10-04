"""
NIST SP 800-53 Rev 5 Controls Knowledge Base
Covers selected controls from 20 control families relevant to application security.
Structured for semantic embedding and RAG retrieval.
"""

NIST_SP800_CONTROLS = [

    # ══════════════════════════════════════
    # AC — Access Control
    # ══════════════════════════════════════
    {
        "id": "AC-1",
        "family": "Access Control",
        "title": "Policy and Procedures",
        "description": "Develop, document, and disseminate access control policy addressing purpose, scope, roles, responsibilities, management commitment, and compliance.",
        "sonarqube_keywords": ["access control policy", "authorization policy", "security policy", "governance"],
        "cwe_refs": [],
    },
    {
        "id": "AC-2",
        "family": "Access Control",
        "title": "Account Management",
        "description": "Manage system accounts including identifying account types, establishing conditions for membership, specifying authorized users, requiring approvals, monitoring account usage, and notifying account managers.",
        "sonarqube_keywords": ["account management", "user account", "orphaned account", "inactive account", "privilege account", "account lifecycle"],
        "cwe_refs": ["CWE-287"],
    },
    {
        "id": "AC-3",
        "family": "Access Control",
        "title": "Access Enforcement",
        "description": "Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
        "sonarqube_keywords": ["access enforcement", "authorization", "access control", "missing authorization", "idor", "insecure direct object", "privilege escalation"],
        "cwe_refs": ["CWE-284", "CWE-285", "CWE-862", "CWE-639"],
    },
    {
        "id": "AC-4",
        "family": "Access Control",
        "title": "Information Flow Enforcement",
        "description": "Enforce approved authorizations for controlling the flow of information within the system and between connected systems based on applicable policy.",
        "sonarqube_keywords": ["information flow", "data flow control", "ssrf", "server-side request forgery", "open redirect", "data exfiltration"],
        "cwe_refs": ["CWE-918", "CWE-601"],
    },
    {
        "id": "AC-6",
        "family": "Access Control",
        "title": "Least Privilege",
        "description": "Employ the principle of least privilege, allowing only authorized accesses for users which are necessary to accomplish assigned organizational tasks.",
        "sonarqube_keywords": ["least privilege", "privilege escalation", "admin access", "root access", "excessive permission", "superuser"],
        "cwe_refs": ["CWE-269", "CWE-250"],
    },
    {
        "id": "AC-7",
        "family": "Access Control",
        "title": "Unsuccessful Logon Attempts",
        "description": "Enforce a limit of consecutive invalid logon attempts and automatically lock the account when the maximum number of unsuccessful attempts is exceeded.",
        "sonarqube_keywords": ["brute force", "account lockout", "login attempt", "failed login", "rate limiting authentication"],
        "cwe_refs": ["CWE-307", "CWE-308"],
    },
    {
        "id": "AC-11",
        "family": "Access Control",
        "title": "Device Lock",
        "description": "Prevent further access to the system by initiating a session lock after a period of inactivity or upon receiving a request from a user.",
        "sonarqube_keywords": ["session timeout", "session lock", "idle session", "session expiry"],
        "cwe_refs": ["CWE-613"],
    },
    {
        "id": "AC-17",
        "family": "Access Control",
        "title": "Remote Access",
        "description": "Establish and document usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access allowed.",
        "sonarqube_keywords": ["remote access", "vpn", "remote connection", "ssh", "rdp", "remote code execution"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # AU — Audit and Accountability
    # ══════════════════════════════════════
    {
        "id": "AU-2",
        "family": "Audit and Accountability",
        "title": "Event Logging",
        "description": "Identify the types of events that the system is capable of logging in support of the audit function and coordinate the event logging function with other organizations requiring audit-related information.",
        "sonarqube_keywords": ["logging", "audit log", "event logging", "missing log", "insufficient logging", "log injection", "no logging"],
        "cwe_refs": ["CWE-778", "CWE-117"],
    },
    {
        "id": "AU-3",
        "family": "Audit and Accountability",
        "title": "Content of Audit Records",
        "description": "Ensure that audit records contain information that establishes what type of event occurred, when the event occurred, where the event occurred, the source of the event, the outcome of the event, and the identity of individuals associated with the event.",
        "sonarqube_keywords": ["audit record", "log content", "event record", "log format", "timestamp", "user identity in log"],
        "cwe_refs": [],
    },
    {
        "id": "AU-9",
        "family": "Audit and Accountability",
        "title": "Protection of Audit Information",
        "description": "Protect audit information and audit tools from unauthorized access, modification, and deletion.",
        "sonarqube_keywords": ["log protection", "log tampering", "log injection", "log forging", "audit protection"],
        "cwe_refs": ["CWE-117"],
    },

    # ══════════════════════════════════════
    # CA — Assessment, Authorization, Monitoring
    # ══════════════════════════════════════
    {
        "id": "CA-7",
        "family": "Assessment Authorization and Monitoring",
        "title": "Continuous Monitoring",
        "description": "Develop a system-level continuous monitoring strategy and implement continuous monitoring in accordance with the organization-level continuous monitoring strategy.",
        "sonarqube_keywords": ["continuous monitoring", "siem", "security monitoring", "anomaly detection", "intrusion detection"],
        "cwe_refs": [],
    },
    {
        "id": "CA-8",
        "family": "Assessment Authorization and Monitoring",
        "title": "Penetration Testing",
        "description": "Conduct penetration testing on organizational systems or system components to identify vulnerabilities and weaknesses.",
        "sonarqube_keywords": ["penetration testing", "pentest", "vulnerability testing", "security testing", "sast", "dast"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # CM — Configuration Management
    # ══════════════════════════════════════
    {
        "id": "CM-2",
        "family": "Configuration Management",
        "title": "Baseline Configuration",
        "description": "Develop, document, and maintain a current baseline configuration of the information system.",
        "sonarqube_keywords": ["configuration", "baseline configuration", "misconfiguration", "hardening", "configuration management"],
        "cwe_refs": ["CWE-1188", "CWE-16"],
    },
    {
        "id": "CM-6",
        "family": "Configuration Management",
        "title": "Configuration Settings",
        "description": "Establish and document configuration settings for technology products employed within the information system that reflect the most restrictive mode consistent with operational requirements.",
        "sonarqube_keywords": ["security configuration", "insecure default", "debug mode", "verbose error", "stack trace exposed", "default credentials", "hardcoded configuration"],
        "cwe_refs": ["CWE-16", "CWE-614", "CWE-1188"],
    },
    {
        "id": "CM-7",
        "family": "Configuration Management",
        "title": "Least Functionality",
        "description": "Configure the information system to provide only essential capabilities.",
        "sonarqube_keywords": ["unnecessary service", "unused port", "unnecessary feature", "attack surface reduction"],
        "cwe_refs": [],
    },
    {
        "id": "CM-8",
        "family": "Configuration Management",
        "title": "System Component Inventory",
        "description": "Develop and document an inventory of system components that accurately reflects the current system.",
        "sonarqube_keywords": ["software inventory", "dependency", "library", "package", "component", "third-party"],
        "cwe_refs": ["CWE-1104"],
    },

    # ══════════════════════════════════════
    # IA — Identification and Authentication
    # ══════════════════════════════════════
    {
        "id": "IA-2",
        "family": "Identification and Authentication",
        "title": "Identification and Authentication (Organizational Users)",
        "description": "Uniquely identify and authenticate organizational users and associate that unique identification with processes acting on behalf of those users.",
        "sonarqube_keywords": ["authentication", "identity", "user identification", "broken authentication", "anonymous access", "missing authentication"],
        "cwe_refs": ["CWE-287", "CWE-306"],
    },
    {
        "id": "IA-5",
        "family": "Identification and Authentication",
        "title": "Authenticator Management",
        "description": "Manage information system authenticators by verifying the identity of the individual as part of initial authenticator distribution, establishing initial authenticator content, ensuring that authenticators have sufficient strength of mechanism, and enforcing administrative procedures.",
        "sonarqube_keywords": ["password management", "credential management", "hardcoded password", "default password", "weak password", "plaintext credential", "password storage", "password policy"],
        "cwe_refs": ["CWE-798", "CWE-259", "CWE-521", "CWE-522"],
    },
    {
        "id": "IA-6",
        "family": "Identification and Authentication",
        "title": "Authenticator Feedback",
        "description": "Obscure feedback of authentication information during the authentication process to protect the information from possible exploitation by unauthorized individuals.",
        "sonarqube_keywords": ["password feedback", "password visible", "credential in url", "credential in log", "sensitive data in url"],
        "cwe_refs": ["CWE-200", "CWE-549"],
    },
    {
        "id": "IA-8",
        "family": "Identification and Authentication",
        "title": "Identification and Authentication (Non-Organizational Users)",
        "description": "Uniquely identify and authenticate non-organizational users.",
        "sonarqube_keywords": ["external user authentication", "api authentication", "service authentication", "jwt", "oauth", "saml", "api key"],
        "cwe_refs": ["CWE-287"],
    },

    # ══════════════════════════════════════
    # IR — Incident Response
    # ══════════════════════════════════════
    {
        "id": "IR-4",
        "family": "Incident Response",
        "title": "Incident Handling",
        "description": "Implement an incident handling capability for security incidents that includes preparation, detection and analysis, containment, eradication, and recovery.",
        "sonarqube_keywords": ["incident handling", "incident response", "containment", "eradication", "recovery", "incident management"],
        "cwe_refs": [],
    },
    {
        "id": "IR-5",
        "family": "Incident Response",
        "title": "Incident Monitoring",
        "description": "Track and document information system security incidents.",
        "sonarqube_keywords": ["incident tracking", "incident monitoring", "security incident", "event monitoring"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # RA — Risk Assessment
    # ══════════════════════════════════════
    {
        "id": "RA-3",
        "family": "Risk Assessment",
        "title": "Risk Assessment",
        "description": "Conduct a risk assessment to identify threats and vulnerabilities to organizational operations, organizational assets, and individuals.",
        "sonarqube_keywords": ["risk assessment", "threat", "vulnerability", "impact", "likelihood", "severity"],
        "cwe_refs": [],
    },
    {
        "id": "RA-5",
        "family": "Risk Assessment",
        "title": "Vulnerability Monitoring and Scanning",
        "description": "Monitor and scan for vulnerabilities in the information system and hosted applications and when new vulnerabilities potentially affecting the system are identified and reported.",
        "sonarqube_keywords": ["vulnerability scanning", "sast", "dast", "security scan", "cve", "known vulnerability", "dependency vulnerability"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # SC — System and Communications Protection
    # ══════════════════════════════════════
    {
        "id": "SC-5",
        "family": "System and Communications Protection",
        "title": "Denial of Service Protection",
        "description": "Implement protections against or limit the effects of denial-of-service attacks.",
        "sonarqube_keywords": ["denial of service", "dos", "ddos", "rate limiting", "resource exhaustion", "memory leak"],
        "cwe_refs": ["CWE-400", "CWE-770"],
    },
    {
        "id": "SC-8",
        "family": "System and Communications Protection",
        "title": "Transmission Confidentiality and Integrity",
        "description": "Implement cryptographic mechanisms to prevent unauthorized disclosure and detect changes to information during transmission.",
        "sonarqube_keywords": ["tls", "ssl", "https", "transport security", "unencrypted communication", "clear text", "man in the middle", "certificate validation"],
        "cwe_refs": ["CWE-319", "CWE-326", "CWE-295", "CWE-297"],
    },
    {
        "id": "SC-12",
        "family": "System and Communications Protection",
        "title": "Cryptographic Key Establishment and Management",
        "description": "Establish and manage cryptographic keys when cryptography is employed within the information system.",
        "sonarqube_keywords": ["key management", "hardcoded key", "cryptographic key", "key rotation", "key storage"],
        "cwe_refs": ["CWE-321", "CWE-320"],
    },
    {
        "id": "SC-13",
        "family": "System and Communications Protection",
        "title": "Cryptographic Protection",
        "description": "Implement cryptographic uses and type of cryptography required for each use in accordance with applicable federal laws.",
        "sonarqube_keywords": ["encryption", "cryptography", "weak cipher", "aes", "rsa", "md5", "sha1", "weak hash", "des", "rc4", "cryptographic failure"],
        "cwe_refs": ["CWE-327", "CWE-328", "CWE-326"],
    },
    {
        "id": "SC-23",
        "family": "System and Communications Protection",
        "title": "Session Authenticity",
        "description": "Protect the authenticity of communications sessions.",
        "sonarqube_keywords": ["session authenticity", "session management", "csrf", "session fixation", "session hijacking", "cookie security"],
        "cwe_refs": ["CWE-352", "CWE-384", "CWE-614"],
    },
    {
        "id": "SC-28",
        "family": "System and Communications Protection",
        "title": "Protection of Information at Rest",
        "description": "Implement cryptographic mechanisms to prevent unauthorized disclosure and modification of information at rest.",
        "sonarqube_keywords": ["data at rest", "database encryption", "disk encryption", "unencrypted storage", "plaintext storage", "sensitive data storage"],
        "cwe_refs": ["CWE-312", "CWE-313", "CWE-311"],
    },

    # ══════════════════════════════════════
    # SI — System and Information Integrity
    # ══════════════════════════════════════
    {
        "id": "SI-2",
        "family": "System and Information Integrity",
        "title": "Flaw Remediation",
        "description": "Identify, report, and correct information system flaws; test software and firmware updates related to flaw remediation for effectiveness and potential side effects.",
        "sonarqube_keywords": ["flaw remediation", "patch", "fix", "remediation", "vulnerability fix", "security patch", "update"],
        "cwe_refs": [],
    },
    {
        "id": "SI-3",
        "family": "System and Information Integrity",
        "title": "Malicious Code Protection",
        "description": "Implement malicious code protection mechanisms at information system entry and exit points and at workstations, servers, or mobile computing devices on the network.",
        "sonarqube_keywords": ["malicious code", "malware", "code injection", "command injection", "exec", "remote code execution", "deserialization", "shell injection"],
        "cwe_refs": ["CWE-78", "CWE-502", "CWE-94"],
    },
    {
        "id": "SI-10",
        "family": "System and Information Integrity",
        "title": "Information Input Validation",
        "description": "Check the validity of all information input to the information system.",
        "sonarqube_keywords": ["input validation", "unvalidated input", "injection", "sql injection", "xss", "path traversal", "xxe", "missing validation"],
        "cwe_refs": ["CWE-20", "CWE-89", "CWE-79", "CWE-22", "CWE-611"],
    },
    {
        "id": "SI-16",
        "family": "System and Information Integrity",
        "title": "Memory Protection",
        "description": "Implement the following controls to protect the system memory from unauthorized code execution.",
        "sonarqube_keywords": ["memory protection", "buffer overflow", "heap overflow", "stack overflow", "out of bounds", "memory corruption"],
        "cwe_refs": ["CWE-119", "CWE-125", "CWE-787", "CWE-120"],
    },

    # ══════════════════════════════════════
    # SA — System and Services Acquisition
    # ══════════════════════════════════════
    {
        "id": "SA-11",
        "family": "System and Services Acquisition",
        "title": "Developer Testing and Evaluation",
        "description": "Require the developer of the information system, system component, or information system service to implement a security assessment plan and conduct unit, integration, system, and regression testing.",
        "sonarqube_keywords": ["developer testing", "sast", "security test", "code analysis", "security review", "vulnerability testing"],
        "cwe_refs": [],
    },
    {
        "id": "SA-15",
        "family": "System and Services Acquisition",
        "title": "Development Process, Standards, and Tools",
        "description": "Require that the developer uses a documented development process that explicitly addresses security requirements, identifies and resolves security flaws, and documents the results.",
        "sonarqube_keywords": ["secure sdlc", "development process", "coding standard", "secure coding", "security requirement"],
        "cwe_refs": [],
    },
]

# Quick lookup by ID
NIST_SP800_BY_ID = {c["id"]: c for c in NIST_SP800_CONTROLS}

# Group by family
NIST_SP800_BY_FAMILY = {}
for c in NIST_SP800_CONTROLS:
    NIST_SP800_BY_FAMILY.setdefault(c["family"], []).append(c)
