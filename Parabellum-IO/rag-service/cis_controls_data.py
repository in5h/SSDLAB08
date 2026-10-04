"""
CIS Controls v8 Knowledge Base
Covers all 18 Controls with Implementation Group 1 and IG2 Safeguards
Structured for semantic embedding and RAG retrieval.
"""

CIS_CONTROLS = [

    # ══════════════════════════════════════
    # CIS Control 1: Inventory and Control of Enterprise Assets
    # ══════════════════════════════════════
    {
        "id": "CIS-1",
        "ig_level": "IG1",
        "title": "Inventory and Control of Enterprise Assets",
        "description": "Actively manage (inventory, track, and correct) all enterprise assets connected to the infrastructure physically, virtually, remotely, and those within cloud environments to know the totality of assets that need to be monitored and protected.",
        "sonarqube_keywords": ["asset inventory", "hardware inventory", "device management", "asset tracking"],
        "cwe_refs": [],
    },
    {
        "id": "CIS-1.1",
        "ig_level": "IG1",
        "title": "Establish and Maintain Detailed Enterprise Asset Inventory",
        "description": "Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with potential to store, process or transmit data.",
        "sonarqube_keywords": ["asset inventory", "system inventory", "endpoint inventory"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # CIS Control 2: Inventory and Control of Software Assets
    # ══════════════════════════════════════
    {
        "id": "CIS-2",
        "ig_level": "IG1",
        "title": "Inventory and Control of Software Assets",
        "description": "Actively manage (inventory, track, and correct) all software on the network so that only authorized software is installed and can execute, and that unauthorized and unmanaged software is found and prevented from installation or execution.",
        "sonarqube_keywords": ["software inventory", "dependency", "library", "package", "third-party", "component", "outdated"],
        "cwe_refs": ["CWE-1104"],
    },
    {
        "id": "CIS-2.2",
        "ig_level": "IG1",
        "title": "Ensure Authorized Software is Currently Supported",
        "description": "Ensure that only currently supported software is designated as authorized in the software inventory for enterprise assets.",
        "sonarqube_keywords": ["outdated library", "end of life", "deprecated", "unsupported software", "known vulnerability", "cve"],
        "cwe_refs": ["CWE-1104"],
    },

    # ══════════════════════════════════════
    # CIS Control 3: Data Protection
    # ══════════════════════════════════════
    {
        "id": "CIS-3",
        "ig_level": "IG1",
        "title": "Data Protection",
        "description": "Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.",
        "sonarqube_keywords": ["data protection", "data classification", "sensitive data", "pii", "data handling", "data lifecycle"],
        "cwe_refs": ["CWE-200", "CWE-312"],
    },
    {
        "id": "CIS-3.3",
        "ig_level": "IG1",
        "title": "Configure Data Access Control Lists",
        "description": "Configure data access control lists based on a user's need to know. Apply data access control lists, also known as access permissions, to local and remote file systems, databases, and applications.",
        "sonarqube_keywords": ["access control list", "data access control", "authorization", "idor", "insecure direct object"],
        "cwe_refs": ["CWE-284", "CWE-285"],
    },
    {
        "id": "CIS-3.6",
        "ig_level": "IG1",
        "title": "Encrypt Data on End-User Devices",
        "description": "Encrypt data on end-user devices containing sensitive data.",
        "sonarqube_keywords": ["encryption", "data at rest", "device encryption", "disk encryption"],
        "cwe_refs": ["CWE-311", "CWE-312"],
    },
    {
        "id": "CIS-3.10",
        "ig_level": "IG2",
        "title": "Encrypt Sensitive Data in Transit",
        "description": "Encrypt sensitive data in transit using only authenticated protocols with at least TLS 1.2.",
        "sonarqube_keywords": ["tls", "ssl", "https", "transport security", "unencrypted communication", "http", "clear text", "man in the middle"],
        "cwe_refs": ["CWE-319", "CWE-326", "CWE-295"],
    },
    {
        "id": "CIS-3.11",
        "ig_level": "IG2",
        "title": "Encrypt Sensitive Data at Rest",
        "description": "Encrypt sensitive data at rest on servers, applications, and databases containing sensitive data.",
        "sonarqube_keywords": ["data at rest", "database encryption", "plaintext storage", "unencrypted storage", "hardcoded secret", "api key in code"],
        "cwe_refs": ["CWE-312", "CWE-313", "CWE-311"],
    },

    # ══════════════════════════════════════
    # CIS Control 4: Secure Configuration
    # ══════════════════════════════════════
    {
        "id": "CIS-4",
        "ig_level": "IG1",
        "title": "Secure Configuration of Enterprise Assets and Software",
        "description": "Establish and maintain the secure configuration of enterprise assets and software.",
        "sonarqube_keywords": ["secure configuration", "configuration management", "hardening", "baseline", "misconfiguration"],
        "cwe_refs": ["CWE-1188", "CWE-16"],
    },
    {
        "id": "CIS-4.1",
        "ig_level": "IG1",
        "title": "Establish and Maintain a Secure Configuration Process",
        "description": "Establish and maintain a secure configuration process for enterprise assets and software.",
        "sonarqube_keywords": ["configuration process", "secure configuration", "hardening standard", "security baseline"],
        "cwe_refs": [],
    },
    {
        "id": "CIS-4.2",
        "ig_level": "IG1",
        "title": "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
        "description": "Establish and maintain a secure configuration process for network devices.",
        "sonarqube_keywords": ["network configuration", "firewall configuration", "network hardening", "router configuration"],
        "cwe_refs": [],
    },
    {
        "id": "CIS-4.8",
        "ig_level": "IG1",
        "title": "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
        "description": "Uninstall or disable unnecessary services on enterprise assets and software, such as an unused file sharing service, web application module, or service function.",
        "sonarqube_keywords": ["unnecessary service", "debug mode", "unused functionality", "exposed service", "unnecessary port"],
        "cwe_refs": ["CWE-1188"],
    },

    # ══════════════════════════════════════
    # CIS Control 5: Account Management
    # ══════════════════════════════════════
    {
        "id": "CIS-5",
        "ig_level": "IG1",
        "title": "Account Management",
        "description": "Use processes and tools to assign and manage authorization to credentials for user accounts including administrator accounts as well as service and application accounts.",
        "sonarqube_keywords": ["account management", "user account", "credential management", "service account", "privileged account"],
        "cwe_refs": ["CWE-287"],
    },
    {
        "id": "CIS-5.2",
        "ig_level": "IG1",
        "title": "Use Unique Passwords",
        "description": "Use unique passwords for all enterprise assets. Best practice implementation includes, at minimum, an 8-character password for accounts using MFA and a 14-character password for accounts not using MFA.",
        "sonarqube_keywords": ["password", "weak password", "default password", "hardcoded password", "credential", "plaintext password"],
        "cwe_refs": ["CWE-521", "CWE-798", "CWE-259"],
    },
    {
        "id": "CIS-5.4",
        "ig_level": "IG1",
        "title": "Restrict Administrator Privileges to Dedicated Administrator Accounts",
        "description": "Restrict administrator privileges to dedicated administrator accounts on enterprise assets.",
        "sonarqube_keywords": ["admin privilege", "root access", "privileged account", "least privilege", "privilege escalation", "sudo"],
        "cwe_refs": ["CWE-269", "CWE-250"],
    },

    # ══════════════════════════════════════
    # CIS Control 6: Access Control Management
    # ══════════════════════════════════════
    {
        "id": "CIS-6",
        "ig_level": "IG1",
        "title": "Access Control Management",
        "description": "Use processes and tools to create, assign, manage, and revoke access credentials and privileges for user, administrator, and service/application accounts.",
        "sonarqube_keywords": ["access control", "access management", "authorization", "rbac", "permission management"],
        "cwe_refs": ["CWE-284", "CWE-285"],
    },
    {
        "id": "CIS-6.3",
        "ig_level": "IG1",
        "title": "Require MFA for Externally-Exposed Applications",
        "description": "Require all externally-exposed enterprise or third-party applications to enforce MFA, where supported.",
        "sonarqube_keywords": ["mfa", "multi-factor authentication", "two-factor", "2fa", "authentication"],
        "cwe_refs": ["CWE-308"],
    },
    {
        "id": "CIS-6.5",
        "ig_level": "IG1",
        "title": "Require MFA for Administrative Access",
        "description": "Require MFA for all administrative access accounts.",
        "sonarqube_keywords": ["mfa admin", "admin authentication", "privileged access authentication"],
        "cwe_refs": ["CWE-308"],
    },
    {
        "id": "CIS-6.8",
        "ig_level": "IG2",
        "title": "Define and Maintain Role-Based Access Control",
        "description": "Define and maintain role-based access control, through determining and documenting the access rights necessary for each role within the enterprise to successfully carry out its assigned duties.",
        "sonarqube_keywords": ["rbac", "role based access", "role assignment", "access rights", "permission", "authorization"],
        "cwe_refs": ["CWE-285"],
    },

    # ══════════════════════════════════════
    # CIS Control 7: Continuous Vulnerability Management
    # ══════════════════════════════════════
    {
        "id": "CIS-7",
        "ig_level": "IG1",
        "title": "Continuous Vulnerability Management",
        "description": "Develop a plan to continuously assess and track vulnerabilities on all enterprise assets within the enterprise's infrastructure, in order to remediate, and minimize, the window of opportunity for attackers.",
        "sonarqube_keywords": ["vulnerability management", "vulnerability scanning", "patch management", "cve", "remediation"],
        "cwe_refs": [],
    },
    {
        "id": "CIS-7.3",
        "ig_level": "IG1",
        "title": "Perform Automated Operating System Patch Management",
        "description": "Perform operating system updates on enterprise assets through automated patch management on a monthly, or more frequent, basis.",
        "sonarqube_keywords": ["patch", "update", "os patch", "security update", "outdated"],
        "cwe_refs": [],
    },
    {
        "id": "CIS-7.4",
        "ig_level": "IG1",
        "title": "Perform Automated Application Patch Management",
        "description": "Perform application updates on enterprise assets through automated patch management on a monthly, or more frequent, basis.",
        "sonarqube_keywords": ["application patch", "library update", "dependency update", "outdated library", "vulnerable dependency"],
        "cwe_refs": ["CWE-1104"],
    },

    # ══════════════════════════════════════
    # CIS Control 8: Audit Log Management
    # ══════════════════════════════════════
    {
        "id": "CIS-8",
        "ig_level": "IG1",
        "title": "Audit Log Management",
        "description": "Collect, alert, review, and retain audit logs of events that could help detect, understand, or recover from an attack.",
        "sonarqube_keywords": ["audit log", "logging", "log management", "log retention", "security log", "event log"],
        "cwe_refs": ["CWE-778"],
    },
    {
        "id": "CIS-8.2",
        "ig_level": "IG1",
        "title": "Collect Audit Logs",
        "description": "Collect audit logs. Ensure that logging is enabled across enterprise assets.",
        "sonarqube_keywords": ["logging", "missing log", "insufficient logging", "log", "no logging", "log injection", "log forging"],
        "cwe_refs": ["CWE-778", "CWE-117"],
    },
    {
        "id": "CIS-8.5",
        "ig_level": "IG1",
        "title": "Collect Detailed Audit Logs",
        "description": "Configure detailed audit logging for enterprise assets containing sensitive data. Include event source, date, username, timestamp, source addresses, destination addresses, and other useful elements.",
        "sonarqube_keywords": ["detailed logging", "audit trail", "event logging", "user activity log"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # CIS Control 9: Email and Web Browser Protections
    # ══════════════════════════════════════
    {
        "id": "CIS-9",
        "ig_level": "IG1",
        "title": "Email and Web Browser Protections",
        "description": "Improve protections and detections of threats from email and web vectors, as these are opportunities for attackers to manipulate human behavior through direct engagement.",
        "sonarqube_keywords": ["email security", "phishing", "web security", "malicious link"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # CIS Control 10: Malware Defenses
    # ══════════════════════════════════════
    {
        "id": "CIS-10",
        "ig_level": "IG1",
        "title": "Malware Defenses",
        "description": "Prevent or control the installation, spread, and execution of malicious applications, code, or scripts on enterprise assets.",
        "sonarqube_keywords": ["malware", "code injection", "command injection", "exec", "remote code execution", "deserialization", "shell injection", "arbitrary code"],
        "cwe_refs": ["CWE-78", "CWE-502", "CWE-94"],
    },

    # ══════════════════════════════════════
    # CIS Control 11: Data Recovery
    # ══════════════════════════════════════
    {
        "id": "CIS-11",
        "ig_level": "IG1",
        "title": "Data Recovery",
        "description": "Establish and maintain data recovery practices sufficient to restore in-scope enterprise assets to a pre-incident and trusted state.",
        "sonarqube_keywords": ["backup", "recovery", "data loss", "restore", "disaster recovery", "rto", "rpo"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # CIS Control 12: Network Infrastructure Management
    # ══════════════════════════════════════
    {
        "id": "CIS-12",
        "ig_level": "IG1",
        "title": "Network Infrastructure Management",
        "description": "Establish, implement, and actively manage network devices in order to prevent attackers from exploiting vulnerable network services and access points.",
        "sonarqube_keywords": ["network security", "firewall", "network management", "ssrf", "network segmentation"],
        "cwe_refs": ["CWE-918"],
    },

    # ══════════════════════════════════════
    # CIS Control 13: Network Monitoring and Defense
    # ══════════════════════════════════════
    {
        "id": "CIS-13",
        "ig_level": "IG1",
        "title": "Network Monitoring and Defense",
        "description": "Operate processes and tooling to establish and maintain comprehensive network monitoring and defense against security threats.",
        "sonarqube_keywords": ["network monitoring", "ids", "ips", "intrusion detection", "traffic analysis", "anomaly detection"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # CIS Control 14: Security Awareness and Skills Training
    # ══════════════════════════════════════
    {
        "id": "CIS-14",
        "ig_level": "IG1",
        "title": "Security Awareness and Skills Training",
        "description": "Establish and maintain a security awareness program to influence behavior among the workforce to be security conscious and properly skilled to reduce cybersecurity risks.",
        "sonarqube_keywords": ["security awareness", "training", "developer training", "security culture"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # CIS Control 15: Service Provider Management
    # ══════════════════════════════════════
    {
        "id": "CIS-15",
        "ig_level": "IG1",
        "title": "Service Provider Management",
        "description": "Develop a process to evaluate service providers who hold sensitive data or are responsible for an enterprise's critical IT platforms or processes.",
        "sonarqube_keywords": ["third party", "supply chain", "vendor", "service provider", "dependency", "open source"],
        "cwe_refs": ["CWE-1104"],
    },

    # ══════════════════════════════════════
    # CIS Control 16: Application Software Security
    # ══════════════════════════════════════
    {
        "id": "CIS-16",
        "ig_level": "IG2",
        "title": "Application Software Security",
        "description": "Manage the security life cycle of in-house developed, hosted, or acquired software in order to prevent, detect, and remediate security weaknesses before they can impact the enterprise.",
        "sonarqube_keywords": ["application security", "secure sdlc", "software security", "security lifecycle"],
        "cwe_refs": [],
    },
    {
        "id": "CIS-16.1",
        "ig_level": "IG2",
        "title": "Establish and Maintain a Secure Application Development Process",
        "description": "Establish and maintain a secure application development process. In the process, address such items as secure application design standards, secure coding practices, developer training, and secure code reviews.",
        "sonarqube_keywords": ["secure coding", "sast", "code review", "secure development", "security training"],
        "cwe_refs": [],
    },
    {
        "id": "CIS-16.2",
        "ig_level": "IG2",
        "title": "Establish and Maintain a Process to Accept and Address Software Vulnerabilities",
        "description": "Establish and maintain a process to accept and address reports of software vulnerabilities, including providing a means for external entities to report.",
        "sonarqube_keywords": ["vulnerability reporting", "bug bounty", "responsible disclosure", "vulnerability management"],
        "cwe_refs": [],
    },
    {
        "id": "CIS-16.4",
        "ig_level": "IG2",
        "title": "Establish and Manage an Inventory of Third-Party Software Components",
        "description": "Establish and manage an updated inventory of third-party components used in development, often referred to as a Bill of Materials.",
        "sonarqube_keywords": ["sbom", "software bill of materials", "third-party library", "dependency inventory", "component inventory"],
        "cwe_refs": ["CWE-1104"],
    },
    {
        "id": "CIS-16.6",
        "ig_level": "IG2",
        "title": "Establish and Maintain a Severity Rating System and Process for Application Vulnerabilities",
        "description": "Establish and maintain a severity rating system and process for application vulnerabilities that facilitates prioritizing the order in which discovered vulnerabilities are fixed.",
        "sonarqube_keywords": ["severity rating", "vulnerability prioritization", "blocker", "critical", "major", "risk rating"],
        "cwe_refs": [],
    },
    {
        "id": "CIS-16.7",
        "ig_level": "IG2",
        "title": "Use Standard Hardening Configuration Templates for Application Infrastructure",
        "description": "Use standard, industry-recommended hardening configuration templates for application infrastructure components.",
        "sonarqube_keywords": ["hardening", "security configuration", "configuration template", "docker hardening", "kubernetes hardening"],
        "cwe_refs": ["CWE-1188", "CWE-16"],
    },
    {
        "id": "CIS-16.9",
        "ig_level": "IG2",
        "title": "Train Developers in Application Security Concepts and Secure Coding",
        "description": "Ensure that all software development personnel receive training in writing secure code for their specific development environment and responsibilities.",
        "sonarqube_keywords": ["developer training", "secure coding", "appsec training", "injection", "xss", "sql injection"],
        "cwe_refs": [],
    },
    {
        "id": "CIS-16.12",
        "ig_level": "IG2",
        "title": "Implement Code-Level Security Checks",
        "description": "Apply static code analysis tools to verify that coding practices meet defined security standards.",
        "sonarqube_keywords": ["static analysis", "sast", "code analysis", "sonarqube", "code quality", "security scan", "injection", "xss", "sql injection", "input validation"],
        "cwe_refs": ["CWE-20", "CWE-89", "CWE-79"],
    },

    # ══════════════════════════════════════
    # CIS Control 17: Incident Response Management
    # ══════════════════════════════════════
    {
        "id": "CIS-17",
        "ig_level": "IG1",
        "title": "Incident Response Management",
        "description": "Establish a program to develop and maintain an incident response capability in order to prepare, detect, and quickly respond to an attack.",
        "sonarqube_keywords": ["incident response", "incident management", "security incident", "response plan"],
        "cwe_refs": [],
    },

    # ══════════════════════════════════════
    # CIS Control 18: Penetration Testing
    # ══════════════════════════════════════
    {
        "id": "CIS-18",
        "ig_level": "IG2",
        "title": "Penetration Testing",
        "description": "Test the effectiveness and resiliency of enterprise assets through identifying and exploiting weaknesses in controls and simulating the objectives and actions of an attacker.",
        "sonarqube_keywords": ["penetration testing", "pentest", "security testing", "vulnerability testing", "sast", "dast", "ethical hacking"],
        "cwe_refs": [],
    },
    {
        "id": "CIS-18.2",
        "ig_level": "IG2",
        "title": "Perform Periodic External Penetration Tests",
        "description": "Perform periodic external penetration tests based on program requirements, no less than annually.",
        "sonarqube_keywords": ["external pentest", "external security test", "vulnerability assessment"],
        "cwe_refs": [],
    },
    {
        "id": "CIS-18.3",
        "ig_level": "IG2",
        "title": "Remediate Penetration Test Findings",
        "description": "Remediate penetration test findings based on the enterprise's policy for remediation scope and prioritization.",
        "sonarqube_keywords": ["remediation", "fix", "patch", "vulnerability remediation", "security fix"],
        "cwe_refs": [],
    },
]

# Quick lookup by ID
CIS_BY_ID = {c["id"]: c for c in CIS_CONTROLS}

# Group by IG level
CIS_BY_IG = {}
for c in CIS_CONTROLS:
    CIS_BY_IG.setdefault(c["ig_level"], []).append(c)
