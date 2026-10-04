"""
ISO 27001:2022 Annex A Controls Knowledge Base
Covers the selected controls from domains A.5 through A.8
Structured for semantic embedding and RAG retrieval.
"""

ISO27001_CONTROLS = [

    # ══════════════════════════════════════
    # A.5 — Organizational Controls
    # ══════════════════════════════════════
    {
        "id": "A.5.1",
        "domain": "Organizational Controls",
        "title": "Policies for information security",
        "description": "Information security policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and interested parties, and reviewed at planned intervals or if significant changes occur.",
        "sonarqube_keywords": ["security policy", "governance", "policy violation", "compliance", "policy enforcement"],
        "cwe_refs": [],
    },
    {
        "id": "A.5.2",
        "domain": "Organizational Controls",
        "title": "Information security roles and responsibilities",
        "description": "Information security roles and responsibilities shall be defined and allocated according to the organization needs.",
        "sonarqube_keywords": ["role", "responsibility", "access control", "privilege", "ownership"],
        "cwe_refs": [],
    },
    {
        "id": "A.5.7",
        "domain": "Organizational Controls",
        "title": "Threat intelligence",
        "description": "Information relating to information security threats shall be collected and analysed to produce threat intelligence.",
        "sonarqube_keywords": ["threat intelligence", "cve", "threat feed", "vulnerability disclosure", "nvd"],
        "cwe_refs": [],
    },
    {
        "id": "A.5.8",
        "domain": "Organizational Controls",
        "title": "Information security in project management",
        "description": "Information security shall be integrated into project management.",
        "sonarqube_keywords": ["sdlc", "secure development", "project security", "sast", "security requirement"],
        "cwe_refs": [],
    },
    {
        "id": "A.5.14",
        "domain": "Organizational Controls",
        "title": "Information transfer",
        "description": "Information transfer rules, procedures, or agreements shall be in place for all types of transfer facilities within the organization and between the organization and other parties.",
        "sonarqube_keywords": ["data transfer", "data leak", "api", "unencrypted communication", "tls", "http", "clear text"],
        "cwe_refs": ["CWE-319", "CWE-311"],
    },
    {
        "id": "A.5.15",
        "domain": "Organizational Controls",
        "title": "Access control",
        "description": "Rules to control physical and logical access to information and other associated assets shall be established and implemented based on business and information security requirements.",
        "sonarqube_keywords": ["access control", "authorization", "privilege escalation", "least privilege", "rbac", "idor", "permission"],
        "cwe_refs": ["CWE-284", "CWE-285", "CWE-269", "CWE-639"],
    },
    {
        "id": "A.5.16",
        "domain": "Organizational Controls",
        "title": "Identity management",
        "description": "The full life cycle of identities shall be managed.",
        "sonarqube_keywords": ["identity", "user management", "account lifecycle", "orphaned account", "inactive account"],
        "cwe_refs": ["CWE-287"],
    },
    {
        "id": "A.5.17",
        "domain": "Organizational Controls",
        "title": "Authentication information",
        "description": "Allocation and management of authentication information shall be controlled by a management process, including advising personnel on appropriate handling of authentication information.",
        "sonarqube_keywords": ["password", "credential", "hardcoded password", "default password", "weak password", "plaintext password", "stored credential"],
        "cwe_refs": ["CWE-798", "CWE-259", "CWE-321", "CWE-522"],
    },
    {
        "id": "A.5.20",
        "domain": "Organizational Controls",
        "title": "Addressing information security within supplier agreements",
        "description": "Relevant information security requirements shall be established and agreed with each supplier based on the type of supplier relationship.",
        "sonarqube_keywords": ["third party", "supply chain", "vendor", "dependency", "open source", "library"],
        "cwe_refs": ["CWE-1104"],
    },
    {
        "id": "A.5.23",
        "domain": "Organizational Controls",
        "title": "Information security for use of cloud services",
        "description": "Processes for acquisition, use, management and exit from cloud services shall be established in accordance with the organization's information security requirements.",
        "sonarqube_keywords": ["cloud", "s3", "blob storage", "cloud misconfiguration", "public bucket", "cloud access"],
        "cwe_refs": ["CWE-1188"],
    },
    {
        "id": "A.5.24",
        "domain": "Organizational Controls",
        "title": "Information security incident management planning and preparation",
        "description": "The organization shall plan and prepare for managing information security incidents by defining, establishing and communicating information security incident management processes, roles and responsibilities.",
        "sonarqube_keywords": ["incident management", "incident response plan", "incident preparation", "security incident"],
        "cwe_refs": [],
    },
    {
        "id": "A.5.25",
        "domain": "Organizational Controls",
        "title": "Assessment and decision on information security events",
        "description": "The organization shall assess information security events and decide if they are to be categorized as information security incidents.",
        "sonarqube_keywords": ["incident triage", "event assessment", "severity", "blocker", "critical finding", "anomaly"],
        "cwe_refs": [],
    },
    {
        "id": "A.5.26",
        "domain": "Organizational Controls",
        "title": "Response to information security incidents",
        "description": "Information security incidents shall be responded to in accordance with the documented procedures.",
        "sonarqube_keywords": ["incident response", "remediation", "fix", "patch", "containment", "eradication"],
        "cwe_refs": [],
    },
    {
        "id": "A.5.28",
        "domain": "Organizational Controls",
        "title": "Collection of evidence",
        "description": "The organization shall establish and implement procedures for the identification, collection, acquisition, and preservation of evidence related to information security events.",
        "sonarqube_keywords": ["evidence", "forensics", "audit log", "logging", "log retention", "chain of custody"],
        "cwe_refs": ["CWE-778"],
    },

    # ══════════════════════════════════════
    # A.6 — People Controls
    # ══════════════════════════════════════
    {
        "id": "A.6.1",
        "domain": "People Controls",
        "title": "Screening",
        "description": "Background verification checks on all candidates shall be carried out prior to joining the organization and on an ongoing basis.",
        "sonarqube_keywords": ["personnel security", "background check", "vetting"],
        "cwe_refs": [],
    },
    {
        "id": "A.6.3",
        "domain": "People Controls",
        "title": "Information security awareness, education and training",
        "description": "Personnel of the organization and relevant interested parties shall receive appropriate information security awareness, education and training and regular updates of the organization's information security policy.",
        "sonarqube_keywords": ["security awareness", "training", "developer training", "secure coding training"],
        "cwe_refs": [],
    },
    {
        "id": "A.6.8",
        "domain": "People Controls",
        "title": "Information security event reporting",
        "description": "The organization shall provide a mechanism for personnel to report observed or suspected information security events through appropriate channels in a timely manner.",
        "sonarqube_keywords": ["security event reporting", "vulnerability reporting", "disclosure", "bug report"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # A.7 — Physical Controls
    # ══════════════════════════════════════
    {
        "id": "A.7.1",
        "domain": "Physical Controls",
        "title": "Physical security perimeters",
        "description": "Security perimeters shall be defined and used to protect areas that contain information and other associated assets.",
        "sonarqube_keywords": ["physical security", "perimeter", "facility access"],
        "cwe_refs": [],
    },
    {
        "id": "A.7.9",
        "domain": "Physical Controls",
        "title": "Security of assets off-premises",
        "description": "Off-site assets shall be protected.",
        "sonarqube_keywords": ["off-premise", "remote access", "vpn", "endpoint security", "mobile device"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # A.8 — Technological Controls
    # ══════════════════════════════════════
    {
        "id": "A.8.2",
        "domain": "Technological Controls",
        "title": "Privileged access rights",
        "description": "The allocation and use of privileged access rights shall be restricted and managed.",
        "sonarqube_keywords": ["privilege escalation", "admin access", "root", "sudo", "superuser", "privileged account", "least privilege"],
        "cwe_refs": ["CWE-269", "CWE-250"],
    },
    {
        "id": "A.8.3",
        "domain": "Technological Controls",
        "title": "Information access restriction",
        "description": "Access to information and other associated assets shall be restricted in accordance with the established topic-specific policy on access control.",
        "sonarqube_keywords": ["access restriction", "data exposure", "unauthorized access", "sensitive data", "information disclosure", "idor"],
        "cwe_refs": ["CWE-200", "CWE-285", "CWE-639"],
    },
    {
        "id": "A.8.4",
        "domain": "Technological Controls",
        "title": "Access to source code",
        "description": "Read and write access to source code, development tools and software libraries shall be appropriately managed.",
        "sonarqube_keywords": ["source code access", "repository access", "code repository", "git", "svn", "version control"],
        "cwe_refs": [],
    },
    {
        "id": "A.8.5",
        "domain": "Technological Controls",
        "title": "Secure authentication",
        "description": "Secure authentication technologies and procedures shall be implemented based on information access restrictions and the topic-specific policy on access control.",
        "sonarqube_keywords": ["authentication", "mfa", "multi-factor", "jwt", "session", "authentication bypass", "broken authentication", "anonymous access", "session fixation"],
        "cwe_refs": ["CWE-287", "CWE-306", "CWE-384"],
    },
    {
        "id": "A.8.6",
        "domain": "Technological Controls",
        "title": "Capacity management",
        "description": "The use of resources shall be monitored and adjusted in line with current and expected capacity requirements.",
        "sonarqube_keywords": ["capacity", "resource management", "performance", "memory leak", "resource exhaustion", "dos"],
        "cwe_refs": ["CWE-400"],
    },
    {
        "id": "A.8.7",
        "domain": "Technological Controls",
        "title": "Protection against malware",
        "description": "Protection against malware shall be implemented and supported by appropriate user awareness.",
        "sonarqube_keywords": ["malware", "antivirus", "code injection", "command injection", "exec", "remote code execution", "deserialization"],
        "cwe_refs": ["CWE-78", "CWE-502", "CWE-94"],
    },
    {
        "id": "A.8.8",
        "domain": "Technological Controls",
        "title": "Management of technical vulnerabilities",
        "description": "Information about technical vulnerabilities of information systems in use shall be obtained in a timely fashion, the organization's exposure to such vulnerabilities evaluated and appropriate measures taken.",
        "sonarqube_keywords": ["vulnerability management", "patch", "cve", "known vulnerability", "outdated library", "dependency vulnerability", "update"],
        "cwe_refs": ["CWE-1104"],
    },
    {
        "id": "A.8.9",
        "domain": "Technological Controls",
        "title": "Configuration management",
        "description": "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.",
        "sonarqube_keywords": ["configuration", "misconfiguration", "default configuration", "hardening", "insecure default", "debug mode", "verbose error", "stack trace exposed"],
        "cwe_refs": ["CWE-1188", "CWE-16", "CWE-614"],
    },
    {
        "id": "A.8.10",
        "domain": "Technological Controls",
        "title": "Information deletion",
        "description": "Information stored in information systems, devices or in any other storage media shall be deleted when no longer required.",
        "sonarqube_keywords": ["data deletion", "data retention", "sensitive data removal", "data erasure", "gdpr"],
        "cwe_refs": [],
    },
    {
        "id": "A.8.11",
        "domain": "Technological Controls",
        "title": "Data masking",
        "description": "Data masking shall be used in accordance with the organization's topic-specific policy on access control and other related topic-specific policies, and business requirements.",
        "sonarqube_keywords": ["data masking", "data anonymization", "pii", "sensitive data", "personally identifiable information", "redaction"],
        "cwe_refs": ["CWE-200", "CWE-312"],
    },
    {
        "id": "A.8.12",
        "domain": "Technological Controls",
        "title": "Data leakage prevention",
        "description": "Data leakage prevention measures shall be applied to systems, networks and any other devices that process, store or transmit sensitive information.",
        "sonarqube_keywords": ["data leakage", "dlp", "sensitive data exposure", "data exfiltration", "information disclosure", "log sensitive data"],
        "cwe_refs": ["CWE-200", "CWE-532"],
    },
    {
        "id": "A.8.13",
        "domain": "Technological Controls",
        "title": "Information backup",
        "description": "Backup copies of information, software and systems shall be maintained and regularly tested in accordance with the agreed topic-specific policy on backup.",
        "sonarqube_keywords": ["backup", "recovery", "data loss", "availability", "restore"],
        "cwe_refs": [],
    },
    {
        "id": "A.8.15",
        "domain": "Technological Controls",
        "title": "Logging",
        "description": "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.",
        "sonarqube_keywords": ["logging", "audit log", "log", "missing log", "insufficient logging", "log injection", "log forging", "no logging"],
        "cwe_refs": ["CWE-117", "CWE-778"],
    },
    {
        "id": "A.8.16",
        "domain": "Technological Controls",
        "title": "Monitoring activities",
        "description": "Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.",
        "sonarqube_keywords": ["monitoring", "anomaly detection", "siem", "intrusion detection", "ids", "ips", "network monitoring"],
        "cwe_refs": [],
    },
    {
        "id": "A.8.20",
        "domain": "Technological Controls",
        "title": "Networks security",
        "description": "Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.",
        "sonarqube_keywords": ["network security", "firewall", "network segmentation", "ssrf", "request forgery", "unauthorized network access"],
        "cwe_refs": ["CWE-918"],
    },
    {
        "id": "A.8.21",
        "domain": "Technological Controls",
        "title": "Security of network services",
        "description": "Security mechanisms, service levels and service requirements of network services shall be identified, implemented and monitored.",
        "sonarqube_keywords": ["network service", "api security", "service authentication", "tls", "ssl", "https", "transport security"],
        "cwe_refs": ["CWE-319", "CWE-326", "CWE-295"],
    },
    {
        "id": "A.8.24",
        "domain": "Technological Controls",
        "title": "Use of cryptography",
        "description": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
        "sonarqube_keywords": ["encryption", "cryptography", "weak cipher", "aes", "rsa", "md5", "sha1", "weak hash", "cryptographic failure", "key management"],
        "cwe_refs": ["CWE-327", "CWE-328", "CWE-326", "CWE-311"],
    },
    {
        "id": "A.8.25",
        "domain": "Technological Controls",
        "title": "Secure development life cycle",
        "description": "Rules for the secure development of software and systems shall be established and applied.",
        "sonarqube_keywords": ["secure sdlc", "secure development", "code review", "sast", "dast", "security testing", "input validation"],
        "cwe_refs": ["CWE-20", "CWE-89", "CWE-79"],
    },
    {
        "id": "A.8.26",
        "domain": "Technological Controls",
        "title": "Application security requirements",
        "description": "Information security requirements shall be identified, specified and approved when developing or acquiring applications.",
        "sonarqube_keywords": ["security requirement", "application security", "security specification", "security acceptance criteria"],
        "cwe_refs": [],
    },
    {
        "id": "A.8.27",
        "domain": "Technological Controls",
        "title": "Secure system architecture and engineering principles",
        "description": "Principles for engineering secure systems shall be established, documented, maintained and applied to any information system development activities.",
        "sonarqube_keywords": ["secure architecture", "defence in depth", "security principle", "least privilege", "separation of duties"],
        "cwe_refs": [],
    },
    {
        "id": "A.8.28",
        "domain": "Technological Controls",
        "title": "Secure coding",
        "description": "Secure coding principles shall be applied to software development.",
        "sonarqube_keywords": ["secure coding", "injection", "sql injection", "xss", "cross-site scripting", "csrf", "path traversal", "buffer overflow", "input validation", "output encoding", "sanitization"],
        "cwe_refs": ["CWE-89", "CWE-79", "CWE-352", "CWE-22", "CWE-20"],
    },
    {
        "id": "A.8.29",
        "domain": "Technological Controls",
        "title": "Security testing in development and acceptance",
        "description": "Security testing processes shall be defined and implemented in the development life cycle.",
        "sonarqube_keywords": ["security testing", "penetration testing", "vulnerability testing", "sast", "dast", "security scan"],
        "cwe_refs": [],
    },
    {
        "id": "A.8.30",
        "domain": "Technological Controls",
        "title": "Outsourced development",
        "description": "The organization shall direct, monitor and review the activities related to outsourced system development.",
        "sonarqube_keywords": ["outsourced", "third party development", "vendor code", "supply chain", "dependency"],
        "cwe_refs": ["CWE-1104"],
    },
    {
        "id": "A.8.33",
        "domain": "Technological Controls",
        "title": "Test information",
        "description": "Test information shall be appropriately selected, protected and managed.",
        "sonarqube_keywords": ["test data", "hardcoded test data", "sensitive test data", "production data in test"],
        "cwe_refs": ["CWE-200"],
    },
    {
        "id": "A.8.34",
        "domain": "Technological Controls",
        "title": "Protection of information systems during audit testing",
        "description": "Audit tests and other assurance activities involving assessment of operational systems shall be planned and agreed between the tester and appropriate management.",
        "sonarqube_keywords": ["audit testing", "penetration test", "security audit", "non-disruptive testing"],
        "cwe_refs": [],
    },
]

# Quick lookup by ID
ISO27001_BY_ID = {c["id"]: c for c in ISO27001_CONTROLS}

# Group by domain
ISO27001_BY_DOMAIN = {}
for c in ISO27001_CONTROLS:
    ISO27001_BY_DOMAIN.setdefault(c["domain"], []).append(c)
