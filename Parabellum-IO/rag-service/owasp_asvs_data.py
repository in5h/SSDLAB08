"""
OWASP ASVS v4.0 Knowledge Base
Covers the 14 Verification Chapters (V1–V14) with all security requirements.
Structured for semantic embedding and RAG retrieval.
"""

OWASP_ASVS_CONTROLS = [

    # ══════════════════════════════════════
    # V1 — Architecture, Design and Threat Modelling
    # ══════════════════════════════════════
    {
        "id": "ASVS-V1.1",
        "chapter": "Architecture, Design and Threat Modelling",
        "title": "Secure Software Development Lifecycle",
        "description": "Verify the use of a secure software development lifecycle that addresses security in all phases of development. Security requirements must be defined and reviewed. Threat modelling must be performed for new features.",
        "sonarqube_keywords": ["sdlc", "secure development", "security requirement", "threat model", "security design review"],
        "cwe_refs": [],
    },
    {
        "id": "ASVS-V1.2",
        "chapter": "Architecture, Design and Threat Modelling",
        "title": "Authentication Architecture",
        "description": "Verify that all application components use a single, vetted, and tested authentication mechanism. Authentication must use strong server-side controls.",
        "sonarqube_keywords": ["authentication architecture", "centralized authentication", "authentication mechanism", "server-side auth"],
        "cwe_refs": ["CWE-287"],
    },
    {
        "id": "ASVS-V1.4",
        "chapter": "Architecture, Design and Threat Modelling",
        "title": "Access Control Architecture",
        "description": "Verify that trusted enforcement points such as access control gateways, servers, and serverless functions enforce access controls. Do not enforce access controls on the client.",
        "sonarqube_keywords": ["access control architecture", "server-side access control", "client-side authorization bypass"],
        "cwe_refs": ["CWE-602"],
    },

    # ══════════════════════════════════════
    # V2 — Authentication
    # ══════════════════════════════════════
    {
        "id": "ASVS-V2.1",
        "chapter": "Authentication",
        "title": "Password Security",
        "description": "Verify that user set passwords are at least 12 characters in length, allow spaces and special characters, and that there is no upper limit on password length. Passwords must not be stored using reversible or weak hashing algorithms.",
        "sonarqube_keywords": ["password policy", "weak password", "password length", "password storage", "password hash", "md5 password", "sha1 password", "plaintext password"],
        "cwe_refs": ["CWE-521", "CWE-916", "CWE-259"],
    },
    {
        "id": "ASVS-V2.2",
        "chapter": "Authentication",
        "title": "General Authenticator Security",
        "description": "Verify that anti-automation controls are effective at mitigating breached credential testing, brute force, and account lockout attacks. Verify that credential hints are not used.",
        "sonarqube_keywords": ["brute force", "account lockout", "credential stuffing", "rate limiting", "authentication bypass"],
        "cwe_refs": ["CWE-307", "CWE-798"],
    },
    {
        "id": "ASVS-V2.3",
        "chapter": "Authentication",
        "title": "Authenticator Lifecycle",
        "description": "Verify that the system can detect and alert on authentication anomalies such as by country, by device, and recently used IP addresses.",
        "sonarqube_keywords": ["authentication lifecycle", "credential lifecycle", "account provisioning", "password reset", "authenticator management"],
        "cwe_refs": [],
    },
    {
        "id": "ASVS-V2.4",
        "chapter": "Authentication",
        "title": "Credential Storage",
        "description": "Verify that passwords are stored using an approved adaptive one-way hashing algorithm with a work factor of at least 600,000 iterations for PBKDF2, or using bcrypt, scrypt or Argon2id with appropriate cost factors.",
        "sonarqube_keywords": ["password storage", "password hash", "bcrypt", "argon2", "pbkdf2", "scrypt", "md5 hash", "sha1 hash", "weak hash", "hardcoded password", "plaintext credential"],
        "cwe_refs": ["CWE-916", "CWE-327", "CWE-328", "CWE-522"],
    },
    {
        "id": "ASVS-V2.7",
        "chapter": "Authentication",
        "title": "Out of Band Verification",
        "description": "Verify that out of band verifier generated OTPs or other codes have sufficient randomness, expire after a short period, are single-use only, and transmitted via a secure channel.",
        "sonarqube_keywords": ["otp", "one time password", "mfa", "multi-factor authentication", "2fa", "verification code"],
        "cwe_refs": ["CWE-330"],
    },
    {
        "id": "ASVS-V2.8",
        "chapter": "Authentication",
        "title": "Single or Multi Factor One Time Verifier",
        "description": "Verify that time-based OTPs have a defined lifetime before expiring. One-time authentication codes must be invalidated after use.",
        "sonarqube_keywords": ["otp expiry", "one-time token", "token lifetime", "token reuse"],
        "cwe_refs": ["CWE-613"],
    },

    # ══════════════════════════════════════
    # V3 — Session Management
    # ══════════════════════════════════════
    {
        "id": "ASVS-V3.1",
        "chapter": "Session Management",
        "title": "Fundamental Session Management Security",
        "description": "Verify that the application never reveals session tokens in URL parameters or error messages. Session tokens must be stored securely and never transmitted in plaintext.",
        "sonarqube_keywords": ["session management", "session token", "session in url", "session exposure", "cookie security", "session hijacking"],
        "cwe_refs": ["CWE-598", "CWE-614"],
    },
    {
        "id": "ASVS-V3.2",
        "chapter": "Session Management",
        "title": "Session Binding",
        "description": "Verify the application generates a new session token on user authentication. Session tokens must have at least 64 bits of entropy and be stored securely.",
        "sonarqube_keywords": ["session fixation", "session regeneration", "session binding", "session token entropy"],
        "cwe_refs": ["CWE-384", "CWE-330"],
    },
    {
        "id": "ASVS-V3.3",
        "chapter": "Session Management",
        "title": "Session Timeout",
        "description": "Verify that logout and expiration invalidate the session token. Sessions should expire after a defined period of inactivity.",
        "sonarqube_keywords": ["session timeout", "session expiry", "logout", "idle session", "session invalidation"],
        "cwe_refs": ["CWE-613"],
    },
    {
        "id": "ASVS-V3.4",
        "chapter": "Session Management",
        "title": "Cookie-based Session Management",
        "description": "Verify that cookie-based session tokens have the Secure attribute set, use the HttpOnly attribute, and use the SameSite attribute to limit exposure to cross-site request forgery attacks.",
        "sonarqube_keywords": ["cookie security", "secure cookie", "httponly", "samesite", "csrf cookie", "cookie flag"],
        "cwe_refs": ["CWE-614", "CWE-352"],
    },

    # ══════════════════════════════════════
    # V4 — Access Control
    # ══════════════════════════════════════
    {
        "id": "ASVS-V4.1",
        "chapter": "Access Control",
        "title": "General Access Control Design",
        "description": "Verify that the principle of least privilege exists – users should only be able to access functions, data files, URLs, controllers, services, and other resources for which they have specific authorisation.",
        "sonarqube_keywords": ["least privilege", "access control", "authorization", "idor", "insecure direct object", "privilege escalation", "missing authorization"],
        "cwe_refs": ["CWE-284", "CWE-285", "CWE-639", "CWE-862"],
    },
    {
        "id": "ASVS-V4.2",
        "chapter": "Access Control",
        "title": "Operation Level Access Control",
        "description": "Verify that sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating, and deletion of records.",
        "sonarqube_keywords": ["idor", "insecure direct object reference", "object level authorization", "broken object level", "mass assignment"],
        "cwe_refs": ["CWE-639", "CWE-915"],
    },

    # ══════════════════════════════════════
    # V5 — Validation, Sanitization and Encoding
    # ══════════════════════════════════════
    {
        "id": "ASVS-V5.1",
        "chapter": "Validation, Sanitization and Encoding",
        "title": "Input Validation",
        "description": "Verify that the application has defenses against HTTP parameter pollution attacks. Verify that all input is validated using positive validation (allow lists), not negative validation (deny lists or sanitization).",
        "sonarqube_keywords": ["input validation", "positive validation", "allowlist", "whitelist", "deny list", "parameter pollution", "missing validation"],
        "cwe_refs": ["CWE-20", "CWE-235"],
    },
    {
        "id": "ASVS-V5.2",
        "chapter": "Validation, Sanitization and Encoding",
        "title": "Sanitization and Sandboxing",
        "description": "Verify that all untrusted HTML input from WYSIWYG editors or similar is properly sanitized with an HTML sanitizer library or framework feature.",
        "sonarqube_keywords": ["sanitization", "html sanitizer", "xss prevention", "user input sanitization", "sanitize html"],
        "cwe_refs": ["CWE-79", "CWE-116"],
    },
    {
        "id": "ASVS-V5.3",
        "chapter": "Validation, Sanitization and Encoding",
        "title": "Output Encoding and Injection Prevention",
        "description": "Verify that output encoding is relevant for the interpreter and context required. All injection attacks must be prevented including SQL injection, command injection, LDAP injection, XPath injection, and XSS.",
        "sonarqube_keywords": ["output encoding", "xss", "cross-site scripting", "sql injection", "command injection", "ldap injection", "xpath injection", "injection prevention", "html encoding"],
        "cwe_refs": ["CWE-79", "CWE-89", "CWE-78", "CWE-90", "CWE-643", "CWE-116"],
    },
    {
        "id": "ASVS-V5.4",
        "chapter": "Validation, Sanitization and Encoding",
        "title": "Memory, String and Unmanaged Code",
        "description": "Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows.",
        "sonarqube_keywords": ["buffer overflow", "memory safety", "stack overflow", "heap overflow", "memory corruption", "unsafe memory"],
        "cwe_refs": ["CWE-119", "CWE-120", "CWE-125", "CWE-787"],
    },
    {
        "id": "ASVS-V5.5",
        "chapter": "Validation, Sanitization and Encoding",
        "title": "Deserialization Prevention",
        "description": "Verify that serialized objects use integrity checks or are encrypted to prevent hostile object creation or data tampering.",
        "sonarqube_keywords": ["deserialization", "serialization", "insecure deserialization", "object injection", "java deserialization", "pickle"],
        "cwe_refs": ["CWE-502"],
    },

    # ══════════════════════════════════════
    # V6 — Stored Cryptography
    # ══════════════════════════════════════
    {
        "id": "ASVS-V6.1",
        "chapter": "Stored Cryptography",
        "title": "Data Classification",
        "description": "Verify that regulated private data is stored encrypted while at rest, such as Personally Identifiable Information (PII), sensitive personal information, or data assessed likely to be subject to EU's GDPR.",
        "sonarqube_keywords": ["data classification", "pii", "sensitive data", "data at rest", "gdpr", "personal data", "regulated data"],
        "cwe_refs": ["CWE-312"],
    },
    {
        "id": "ASVS-V6.2",
        "chapter": "Stored Cryptography",
        "title": "Algorithms",
        "description": "Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable Padding Oracle attacks. Weak algorithms such as MD5, SHA1, DES, RC4, and RSA-1024 must not be used.",
        "sonarqube_keywords": ["weak cipher", "weak hash", "md5", "sha1", "des", "rc4", "aes", "cryptographic failure", "padding oracle", "rsa-1024"],
        "cwe_refs": ["CWE-327", "CWE-328", "CWE-326"],
    },
    {
        "id": "ASVS-V6.3",
        "chapter": "Stored Cryptography",
        "title": "Random Values",
        "description": "Verify that all random numbers, random file names, random GUIDs, and random strings are generated using the cryptographic module's approved cryptographically secure random number generator.",
        "sonarqube_keywords": ["random number", "weak random", "predictable random", "insecure random", "math.random", "rand"],
        "cwe_refs": ["CWE-330", "CWE-338"],
    },
    {
        "id": "ASVS-V6.4",
        "chapter": "Stored Cryptography",
        "title": "Secret Management",
        "description": "Verify that secrets, API keys, and passwords are not included in source code, or online source code repositories. Secrets must be stored in a vault or encrypted configuration.",
        "sonarqube_keywords": ["hardcoded secret", "api key", "hardcoded password", "private key in code", "secret in code", "credential in source", "password in config"],
        "cwe_refs": ["CWE-798", "CWE-259", "CWE-321"],
    },

    # ══════════════════════════════════════
    # V7 — Error Handling and Logging
    # ══════════════════════════════════════
    {
        "id": "ASVS-V7.1",
        "chapter": "Error Handling and Logging",
        "title": "Log Content",
        "description": "Verify that the application does not log credentials or payment details. Verify that sensitive information is not logged.",
        "sonarqube_keywords": ["log sensitive data", "password in log", "credential in log", "pii in log", "sensitive data logging"],
        "cwe_refs": ["CWE-532"],
    },
    {
        "id": "ASVS-V7.2",
        "chapter": "Error Handling and Logging",
        "title": "Log Processing",
        "description": "Verify that all authentication decisions are logged, with sufficient user context to identify suspicious or malicious accounts.",
        "sonarqube_keywords": ["authentication logging", "security event log", "audit log", "missing log", "insufficient logging"],
        "cwe_refs": ["CWE-778"],
    },
    {
        "id": "ASVS-V7.4",
        "chapter": "Error Handling and Logging",
        "title": "Error Handling",
        "description": "Verify that a generic message is shown when an unexpected or security sensitive error occurs, potentially with a unique ID which support personnel can use to investigate.",
        "sonarqube_keywords": ["error handling", "stack trace exposed", "verbose error", "sensitive data in error", "exception handling", "information disclosure in error"],
        "cwe_refs": ["CWE-209", "CWE-248"],
    },

    # ══════════════════════════════════════
    # V8 — Data Protection
    # ══════════════════════════════════════
    {
        "id": "ASVS-V8.1",
        "chapter": "Data Protection",
        "title": "General Data Protection",
        "description": "Verify that the application protects sensitive data from being cached in server components such as load balancers and application caches.",
        "sonarqube_keywords": ["data protection", "cache control", "sensitive data caching", "no-cache", "browser cache"],
        "cwe_refs": ["CWE-524"],
    },
    {
        "id": "ASVS-V8.2",
        "chapter": "Data Protection",
        "title": "Client-side Data Protection",
        "description": "Verify that sensitive data is not stored in browser storage (localStorage, sessionStorage, IndexedDB), cookie stores, or Flash cookie stores.",
        "sonarqube_keywords": ["client-side storage", "localstorage", "sessionstorage", "sensitive data client", "browser storage"],
        "cwe_refs": ["CWE-922"],
    },
    {
        "id": "ASVS-V8.3",
        "chapter": "Data Protection",
        "title": "Sensitive Private Data",
        "description": "Verify that sensitive data is transmitted to the server in the HTTP message body or headers, and that query string parameters from any HTTP verb do not contain sensitive data.",
        "sonarqube_keywords": ["sensitive data in url", "credential in url", "password in url", "data in query string", "sensitive parameter"],
        "cwe_refs": ["CWE-598", "CWE-200"],
    },

    # ══════════════════════════════════════
    # V9 — Communication
    # ══════════════════════════════════════
    {
        "id": "ASVS-V9.1",
        "chapter": "Communication",
        "title": "Client Communication Security",
        "description": "Verify that TLS is used for all client connectivity, and does not fall back to insecure or unencrypted communications. The application must use TLS 1.2 or higher.",
        "sonarqube_keywords": ["tls", "ssl", "https", "transport security", "unencrypted communication", "http", "clear text", "tls version", "ssl version"],
        "cwe_refs": ["CWE-319", "CWE-326", "CWE-295"],
    },
    {
        "id": "ASVS-V9.2",
        "chapter": "Communication",
        "title": "Server Communication Security",
        "description": "Verify that connections to and from the server use trusted TLS certificates. The application must validate TLS certificates before using them.",
        "sonarqube_keywords": ["certificate validation", "ssl verification", "tls certificate", "hostname verification", "insecure connection", "self-signed certificate"],
        "cwe_refs": ["CWE-295", "CWE-297"],
    },

    # ══════════════════════════════════════
    # V10 — Malicious Code
    # ══════════════════════════════════════
    {
        "id": "ASVS-V10.1",
        "chapter": "Malicious Code",
        "title": "Code Integrity Controls",
        "description": "Verify that a code analysis tool is in use that can detect potentially malicious code, such as time functions, unsafe file operations, or network connections.",
        "sonarqube_keywords": ["malicious code", "code integrity", "static analysis", "sast", "code analysis"],
        "cwe_refs": [],
    },
    {
        "id": "ASVS-V10.2",
        "chapter": "Malicious Code",
        "title": "Malicious Code Search",
        "description": "Verify that the application source code and third party libraries do not contain back doors, Easter eggs, and logic bombs.",
        "sonarqube_keywords": ["backdoor", "logic bomb", "hidden functionality", "malicious functionality", "trojan"],
        "cwe_refs": ["CWE-506"],
    },
    {
        "id": "ASVS-V10.3",
        "chapter": "Malicious Code",
        "title": "Deployed Application Integrity Controls",
        "description": "Verify that if the application has a client or server auto-update feature, updates should be obtained over secure channels and digitally signed.",
        "sonarqube_keywords": ["update integrity", "software update", "digital signature", "code signing", "auto-update security"],
        "cwe_refs": ["CWE-494"],
    },

    # ══════════════════════════════════════
    # V11 — Business Logic
    # ══════════════════════════════════════
    {
        "id": "ASVS-V11.1",
        "chapter": "Business Logic",
        "title": "Business Logic Security",
        "description": "Verify that the application will only process business logic flows for the same user in sequential step order and without skipping steps.",
        "sonarqube_keywords": ["business logic", "workflow bypass", "logic flaw", "race condition", "step bypass"],
        "cwe_refs": ["CWE-840", "CWE-362"],
    },

    # ══════════════════════════════════════
    # V12 — Files and Resources
    # ══════════════════════════════════════
    {
        "id": "ASVS-V12.1",
        "chapter": "Files and Resources",
        "title": "File Upload",
        "description": "Verify that the application will not accept large files that could fill up storage or cause a denial of service.",
        "sonarqube_keywords": ["file upload", "unrestricted upload", "file size limit", "malicious file upload"],
        "cwe_refs": ["CWE-434", "CWE-400"],
    },
    {
        "id": "ASVS-V12.3",
        "chapter": "Files and Resources",
        "title": "File Execution Prevention",
        "description": "Verify that user-submitted filename metadata is not used directly by system or framework filesystems and that a URL API is used to protect against path traversal.",
        "sonarqube_keywords": ["path traversal", "directory traversal", "file inclusion", "lfi", "rfi", "zip slip", "filename injection"],
        "cwe_refs": ["CWE-22", "CWE-23", "CWE-98"],
    },
    {
        "id": "ASVS-V12.4",
        "chapter": "Files and Resources",
        "title": "File Storage",
        "description": "Verify that files obtained from untrusted sources are validated to be of expected type and are not accessible directly as user-supplied content.",
        "sonarqube_keywords": ["file storage", "file validation", "file type validation", "content type", "magic bytes"],
        "cwe_refs": ["CWE-434"],
    },

    # ══════════════════════════════════════
    # V13 — API and Web Service
    # ══════════════════════════════════════
    {
        "id": "ASVS-V13.1",
        "chapter": "API and Web Service",
        "title": "Generic Web Service Security",
        "description": "Verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit different URI or file parsing behavior that could be used in SSRF and RFI attacks.",
        "sonarqube_keywords": ["api security", "web service security", "ssrf", "server-side request forgery", "rfi", "open redirect", "url validation"],
        "cwe_refs": ["CWE-918", "CWE-601"],
    },
    {
        "id": "ASVS-V13.2",
        "chapter": "API and Web Service",
        "title": "RESTful Web Service",
        "description": "Verify that RESTful web services that utilize cookies are protected from Cross-Site Request Forgery via the use of at least one or more of: triple or double submit cookie pattern, CSRF nonces, or ORIGIN request header checks.",
        "sonarqube_keywords": ["csrf", "cross-site request forgery", "rest api security", "csrf token", "csrf protection"],
        "cwe_refs": ["CWE-352"],
    },
    {
        "id": "ASVS-V13.3",
        "chapter": "API and Web Service",
        "title": "SOAP Web Service",
        "description": "Verify that XSD schema validation takes place to ensure a properly formed XML document, followed by validation of each input field before any processing of that data takes place.",
        "sonarqube_keywords": ["xml validation", "soap security", "xxe", "xml external entity", "xpath injection"],
        "cwe_refs": ["CWE-611", "CWE-643"],
    },
    {
        "id": "ASVS-V13.4",
        "chapter": "API and Web Service",
        "title": "GraphQL",
        "description": "Verify that GraphQL or other data layer authorization logic should be implemented at the business logic layer instead of the GraphQL layer.",
        "sonarqube_keywords": ["graphql security", "graphql authorization", "graphql injection", "introspection exposure"],
        "cwe_refs": ["CWE-284"],
    },

    # ══════════════════════════════════════
    # V14 — Configuration
    # ══════════════════════════════════════
    {
        "id": "ASVS-V14.1",
        "chapter": "Configuration",
        "title": "Build and Deploy",
        "description": "Verify that build pipelines warn about out-of-date or insecure components and that appropriate action is taken. Verify that the build pipeline performs automated security testing including SAST and SCA.",
        "sonarqube_keywords": ["build pipeline", "ci/cd security", "sast in pipeline", "sca", "dependency check", "outdated dependency"],
        "cwe_refs": ["CWE-1104"],
    },
    {
        "id": "ASVS-V14.2",
        "chapter": "Configuration",
        "title": "Dependency",
        "description": "Verify that all third-party components used by the application are from expected repositories, and that known vulnerable third-party libraries are not used.",
        "sonarqube_keywords": ["dependency", "third-party library", "vulnerable dependency", "outdated library", "known cve", "open source vulnerability", "package"],
        "cwe_refs": ["CWE-1104"],
    },
    {
        "id": "ASVS-V14.3",
        "chapter": "Configuration",
        "title": "Unintended Security Disclosure",
        "description": "Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features, developer consoles, and unintended security disclosures.",
        "sonarqube_keywords": ["debug mode", "debug in production", "stack trace exposed", "verbose error", "developer console", "insecure default", "misconfiguration", "security headers"],
        "cwe_refs": ["CWE-16", "CWE-209", "CWE-1188"],
    },
    {
        "id": "ASVS-V14.4",
        "chapter": "Configuration",
        "title": "HTTP Security Headers",
        "description": "Verify that every HTTP response contains a Content-Type header. Verify that security headers including X-Frame-Options, X-XSS-Protection, Content-Security-Policy, and Strict-Transport-Security are set appropriately.",
        "sonarqube_keywords": ["security headers", "content security policy", "csp", "x-frame-options", "hsts", "http headers", "missing header", "clickjacking"],
        "cwe_refs": ["CWE-693", "CWE-1021"],
    },
    {
        "id": "ASVS-V14.5",
        "chapter": "Configuration",
        "title": "HTTP Request Header Validation",
        "description": "Verify that the application server only accepts the HTTP methods in use by the application and logs or alerts on any requests using methods not intended for use by the application.",
        "sonarqube_keywords": ["http method", "http verb", "http options", "cors", "allowed methods", "request header validation"],
        "cwe_refs": ["CWE-16"],
    },
]

# Quick lookup by ID
OWASP_ASVS_BY_ID = {c["id"]: c for c in OWASP_ASVS_CONTROLS}

# Group by chapter
OWASP_ASVS_BY_CHAPTER = {}
for c in OWASP_ASVS_CONTROLS:
    OWASP_ASVS_BY_CHAPTER.setdefault(c["chapter"], []).append(c)
