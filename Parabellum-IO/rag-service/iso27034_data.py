"""
ISO 27034 Application Security Controls Knowledge Base
Covers Application Security Controls (ASC) from ISO 27034-1
Structured for semantic embedding and RAG retrieval.
"""

ISO27034_CONTROLS = [

    # ══════════════════════════════════════
    # Application Security Controls — Design
    # ══════════════════════════════════════
    {
        "id": "ISO27034-ASC-1",
        "domain": "Application Security Design",
        "title": "Security requirements elicitation",
        "description": "Security requirements shall be elicited, documented and validated as part of the application development lifecycle. Requirements must cover authentication, authorization, data protection and audit.",
        "sonarqube_keywords": ["security requirement", "missing requirement", "security design", "threat model"],
        "cwe_refs": [],
    },
    {
        "id": "ISO27034-ASC-2",
        "domain": "Application Security Design",
        "title": "Threat modelling for applications",
        "description": "Threat modelling shall be performed to identify potential attack vectors, threat actors and security controls needed for each application component.",
        "sonarqube_keywords": ["threat model", "attack vector", "attack surface", "security architecture"],
        "cwe_refs": [],
    },
    {
        "id": "ISO27034-ASC-3",
        "domain": "Application Security Design",
        "title": "Secure application architecture",
        "description": "Applications shall be designed using security architecture principles including defence-in-depth, least privilege, fail-safe defaults and complete mediation.",
        "sonarqube_keywords": ["defence in depth", "least privilege", "fail safe", "secure architecture", "trust boundary", "privilege separation"],
        "cwe_refs": ["CWE-269", "CWE-250"],
    },
    {
        "id": "ISO27034-ASC-4",
        "domain": "Application Security Design",
        "title": "Application security control specification",
        "description": "All security controls to be implemented in the application shall be specified, including authentication mechanisms, session management, cryptographic controls and input validation.",
        "sonarqube_keywords": ["security control", "authentication control", "session control", "input validation", "sanitization"],
        "cwe_refs": ["CWE-20", "CWE-287"],
    },

    # ══════════════════════════════════════
    # Application Authentication & Access
    # ══════════════════════════════════════
    {
        "id": "ISO27034-ASC-5",
        "domain": "Authentication and Access Control",
        "title": "Application authentication mechanisms",
        "description": "Applications shall implement secure authentication mechanisms. Weak or broken authentication, hardcoded credentials and session weaknesses are prohibited.",
        "sonarqube_keywords": ["authentication bypass", "broken authentication", "hardcoded password", "default password", "weak password", "anonymous access", "missing authentication", "jwt", "session fixation"],
        "cwe_refs": ["CWE-287", "CWE-306", "CWE-798", "CWE-259", "CWE-384"],
    },
    {
        "id": "ISO27034-ASC-6",
        "domain": "Authentication and Access Control",
        "title": "Application authorisation and access control",
        "description": "Applications shall enforce authorisation decisions to prevent unauthorized access to functions or data. Insecure direct object references, privilege escalation and missing access control checks are prohibited.",
        "sonarqube_keywords": ["authorization", "access control", "privilege escalation", "idor", "insecure direct object", "missing authorization", "role check", "permission check"],
        "cwe_refs": ["CWE-284", "CWE-285", "CWE-639", "CWE-862"],
    },
    {
        "id": "ISO27034-ASC-7",
        "domain": "Authentication and Access Control",
        "title": "Session management security",
        "description": "Applications shall implement secure session management including secure session identifiers, session expiry, and protection against session hijacking.",
        "sonarqube_keywords": ["session management", "session hijacking", "session fixation", "csrf", "cookie security", "secure cookie", "httponly", "samesite", "session timeout"],
        "cwe_refs": ["CWE-384", "CWE-352", "CWE-614"],
    },

    # ══════════════════════════════════════
    # Input Validation & Output Encoding
    # ══════════════════════════════════════
    {
        "id": "ISO27034-ASC-8",
        "domain": "Input Validation and Output Encoding",
        "title": "Input validation",
        "description": "All input from untrusted sources shall be validated before processing. Applications shall validate type, length, format and range of all input values.",
        "sonarqube_keywords": ["input validation", "missing validation", "unvalidated input", "injection", "sql injection", "path traversal", "xxe", "ldap injection"],
        "cwe_refs": ["CWE-20", "CWE-89", "CWE-22", "CWE-611", "CWE-90"],
    },
    {
        "id": "ISO27034-ASC-9",
        "domain": "Input Validation and Output Encoding",
        "title": "Output encoding and injection prevention",
        "description": "Application output shall be encoded appropriately to prevent injection attacks. Cross-site scripting and injection vulnerabilities shall be prevented through proper output encoding.",
        "sonarqube_keywords": ["output encoding", "xss", "cross-site scripting", "html encoding", "reflected xss", "stored xss", "dom xss", "injection prevention"],
        "cwe_refs": ["CWE-79", "CWE-80", "CWE-116"],
    },
    {
        "id": "ISO27034-ASC-10",
        "domain": "Input Validation and Output Encoding",
        "title": "Prevention of injection attacks",
        "description": "Applications shall prevent injection vulnerabilities including SQL injection, command injection, LDAP injection and XML injection through parameterised queries and safe API usage.",
        "sonarqube_keywords": ["sql injection", "command injection", "code injection", "ldap injection", "xml injection", "parameterized query", "prepared statement", "exec", "shell injection", "os command"],
        "cwe_refs": ["CWE-89", "CWE-78", "CWE-94", "CWE-90", "CWE-91"],
    },

    # ══════════════════════════════════════
    # Data Security
    # ══════════════════════════════════════
    {
        "id": "ISO27034-ASC-11",
        "domain": "Data Security",
        "title": "Cryptographic controls in applications",
        "description": "Applications shall use approved cryptographic algorithms and key lengths. Weak algorithms (MD5, SHA1, DES, RC4) and hardcoded cryptographic keys shall not be used.",
        "sonarqube_keywords": ["weak cipher", "weak hash", "md5", "sha1", "des", "rc4", "aes", "rsa", "cryptographic failure", "hardcoded key", "key management", "encryption"],
        "cwe_refs": ["CWE-327", "CWE-328", "CWE-326", "CWE-321"],
    },
    {
        "id": "ISO27034-ASC-12",
        "domain": "Data Security",
        "title": "Sensitive data protection",
        "description": "Applications shall protect sensitive data including PII, credentials, and confidential business data both at rest and in transit. Sensitive data shall not be exposed in logs, URLs or error messages.",
        "sonarqube_keywords": ["sensitive data", "pii", "data exposure", "credential exposure", "hardcoded secret", "api key", "private key", "log sensitive data", "url parameter sensitive"],
        "cwe_refs": ["CWE-200", "CWE-312", "CWE-532", "CWE-319"],
    },
    {
        "id": "ISO27034-ASC-13",
        "domain": "Data Security",
        "title": "Transport layer security",
        "description": "All communications transmitting sensitive information shall use strong transport layer security (TLS 1.2+). Insecure protocols, invalid certificates and certificate validation failures are prohibited.",
        "sonarqube_keywords": ["tls", "ssl", "https", "transport security", "unencrypted communication", "http", "clear text", "certificate validation", "ssl verification", "insecure connection"],
        "cwe_refs": ["CWE-319", "CWE-326", "CWE-295", "CWE-297"],
    },

    # ══════════════════════════════════════
    # Error Handling & Logging
    # ══════════════════════════════════════
    {
        "id": "ISO27034-ASC-14",
        "domain": "Error Handling and Logging",
        "title": "Secure error handling",
        "description": "Applications shall handle errors and exceptions securely. Error messages shall not expose sensitive information, stack traces, or system internals to users.",
        "sonarqube_keywords": ["error handling", "exception handling", "stack trace exposed", "verbose error", "sensitive data in error", "information disclosure in error"],
        "cwe_refs": ["CWE-209", "CWE-248", "CWE-391"],
    },
    {
        "id": "ISO27034-ASC-15",
        "domain": "Error Handling and Logging",
        "title": "Security event logging",
        "description": "Applications shall log security-relevant events including authentication failures, access control failures and input validation failures. Logs shall not contain sensitive data.",
        "sonarqube_keywords": ["logging", "audit log", "security event log", "missing log", "insufficient logging", "log injection", "log forging", "no logging"],
        "cwe_refs": ["CWE-117", "CWE-778", "CWE-532"],
    },

    # ══════════════════════════════════════
    # Configuration & Infrastructure
    # ══════════════════════════════════════
    {
        "id": "ISO27034-ASC-16",
        "domain": "Configuration and Infrastructure Security",
        "title": "Secure application configuration",
        "description": "Applications shall be deployed with secure configurations. Default credentials, debug modes, and development settings shall be disabled in production.",
        "sonarqube_keywords": ["misconfiguration", "default configuration", "debug mode", "insecure default", "hardening", "security configuration", "development setting in production"],
        "cwe_refs": ["CWE-1188", "CWE-16"],
    },
    {
        "id": "ISO27034-ASC-17",
        "domain": "Configuration and Infrastructure Security",
        "title": "Dependency and component security",
        "description": "All third-party libraries, frameworks and components used in applications shall be inventoried and kept up-to-date. Known vulnerable dependencies shall be updated or replaced.",
        "sonarqube_keywords": ["dependency", "library", "third-party", "outdated", "vulnerable dependency", "known vulnerability", "cve", "open source"],
        "cwe_refs": ["CWE-1104"],
    },
    {
        "id": "ISO27034-ASC-18",
        "domain": "Configuration and Infrastructure Security",
        "title": "Container and infrastructure security",
        "description": "Containers, orchestration platforms and infrastructure-as-code shall be configured securely. Containers shall not run as root and shall have resource limits set.",
        "sonarqube_keywords": ["container security", "docker", "kubernetes", "root container", "privileged container", "resource limit", "security context"],
        "cwe_refs": ["CWE-250"],
    },

    # ══════════════════════════════════════
    # Testing & Verification
    # ══════════════════════════════════════
    {
        "id": "ISO27034-ASC-19",
        "domain": "Application Security Testing",
        "title": "Static application security testing (SAST)",
        "description": "Static analysis tools shall be used during development to identify security vulnerabilities in source code before deployment.",
        "sonarqube_keywords": ["sast", "static analysis", "code analysis", "security scan", "sonarqube", "vulnerability scan"],
        "cwe_refs": [],
    },
    {
        "id": "ISO27034-ASC-20",
        "domain": "Application Security Testing",
        "title": "Dynamic application security testing (DAST)",
        "description": "Dynamic analysis shall be performed against running applications to identify runtime security vulnerabilities.",
        "sonarqube_keywords": ["dast", "dynamic analysis", "penetration testing", "runtime security", "vulnerability testing"],
        "cwe_refs": [],
    },
    {
        "id": "ISO27034-ASC-21",
        "domain": "Application Security Testing",
        "title": "Security code review",
        "description": "Security-focused code reviews shall be conducted for all code changes introducing security-sensitive functionality.",
        "sonarqube_keywords": ["code review", "security review", "peer review", "manual review"],
        "cwe_refs": [],
    },
]

# Quick lookup by ID
ISO27034_BY_ID = {c["id"]: c for c in ISO27034_CONTROLS}

# Group by domain
ISO27034_BY_DOMAIN = {}
for c in ISO27034_CONTROLS:
    ISO27034_BY_DOMAIN.setdefault(c["domain"], []).append(c)
