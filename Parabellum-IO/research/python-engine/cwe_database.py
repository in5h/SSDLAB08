"""
cwe_database.py
===============
CWE (Common Weakness Enumeration) to NIST CSF 2.0 mapping database.
Contains mappings for vulnerability types, CVSS scoring, and risk assessment.

This module provides a local, static CWE database that maps CWE IDs to:
  - NIST CSF 2.0 controls
  - Risk severity levels
  - Attack vectors
  - Remediation priorities
  - Impact categories

No external dependencies; all data is hardcoded for offline availability.
"""

# ──────────────────────────────────────────────────────────────────
# CWE → NIST CSF 2.0 Mappings with Risk Assessment
# ──────────────────────────────────────────────────────────────────

CWE_DATABASE = {
    # SQL Injection family
    "CWE-89": {
        "name": "SQL Injection",
        "severity": "Critical",
        "cvss_base": 9.8,
        "nist_csf": ["PR.DS-01", "PR.AA-01", "PR.PS-01"],
        "attack_vectors": ["NETWORK", "APPLICATION"],
        "impact_types": ["Confidentiality", "Integrity", "Availability"],
        "risk_keywords": ["Remote Code Execution", "Data Leakage", "Unauthorized Access"],
        "remediation_priority": 1,
        "owasp_category": "A03:2021 – Injection",
        "example": "Improper SQL query construction without parameterized queries or ORM"
    },
    
    # Cross-Site Scripting (XSS)
    "CWE-79": {
        "name": "Improper Neutralization of Input During Web Page Generation (XSS)",
        "severity": "High",
        "cvss_base": 7.1,
        "nist_csf": ["PR.DS-01", "PR.DS-02", "PR.PS-01"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Confidentiality", "Integrity"],
        "risk_keywords": ["Session Hijacking", "Credential Theft", "Malware Distribution"],
        "remediation_priority": 2,
        "owasp_category": "A03:2021 – Injection",
        "example": "Unescaped user input rendered in HTML context"
    },

    # Cross-Site Request Forgery (CSRF)
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "severity": "High",
        "cvss_base": 8.1,
        "nist_csf": ["PR.AA-01", "PR.AA-05"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Integrity", "Availability"],
        "risk_keywords": ["Unauthorized Actions", "Account Takeover", "Data Modification"],
        "remediation_priority": 2,
        "owasp_category": "A01:2021 – Broken Access Control",
        "example": "Missing CSRF tokens in state-changing requests"
    },

    # XXE (XML External Entity) Injection
    "CWE-611": {
        "name": "Improper Restriction of XML External Entity Reference",
        "severity": "Critical",
        "cvss_base": 9.8,
        "nist_csf": ["PR.DS-01", "PR.PS-01"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Confidentiality", "Integrity", "Availability"],
        "risk_keywords": ["File Disclosure", "SSRF", "Denial of Service"],
        "remediation_priority": 1,
        "owasp_category": "A05:2021 – XML External Entity (XXE)",
        "example": "XML parsers with external entity processing enabled"
    },

    # Broken Authentication
    "CWE-287": {
        "name": "Improper Authentication",
        "severity": "Critical",
        "cvss_base": 9.8,
        "nist_csf": ["PR.AA-01", "PR.AA-05"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Confidentiality", "Integrity", "Availability"],
        "risk_keywords": ["Account Takeover", "Unauthorized Access", "Identity Spoofing"],
        "remediation_priority": 1,
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "example": "Missing MFA, weak password policies, session fixation"
    },

    # Broken Access Control
    "CWE-639": {
        "name": "Authorization Bypass Through User-Controlled Key",
        "severity": "High",
        "cvss_base": 7.5,
        "nist_csf": ["PR.AA-05", "PR.AA-01"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Confidentiality", "Integrity"],
        "risk_keywords": ["Privilege Escalation", "Unauthorized Resource Access"],
        "remediation_priority": 2,
        "owasp_category": "A01:2021 – Broken Access Control",
        "example": "Insecure direct object references (IDOR)"
    },

    # Deserialization of Untrusted Data
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "severity": "Critical",
        "cvss_base": 9.8,
        "nist_csf": ["PR.DS-01", "PR.PS-02"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Confidentiality", "Integrity", "Availability"],
        "risk_keywords": ["Remote Code Execution", "Object Injection"],
        "remediation_priority": 1,
        "owasp_category": "A08:2021 – Software and Data Integrity Failures",
        "example": "Java ObjectInputStream, Python pickle with untrusted data"
    },

    # Hardcoded Credentials
    "CWE-798": {
        "name": "Use of Hard-Coded Credentials",
        "severity": "High",
        "cvss_base": 7.5,
        "nist_csf": ["PR.DS-01", "PR.AA-01"],
        "attack_vectors": ["NETWORK", "LOCAL"],
        "impact_types": ["Confidentiality", "Integrity"],
        "risk_keywords": ["Unauthorized Access", "Lateral Movement"],
        "remediation_priority": 2,
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "example": "Passwords or API keys in source code"
    },

    # Weak Cryptography
    "CWE-327": {
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "severity": "High",
        "cvss_base": 7.5,
        "nist_csf": ["PR.DS-02", "PR.DS-01"],
        "attack_vectors": ["NETWORK", "LOCAL"],
        "impact_types": ["Confidentiality"],
        "risk_keywords": ["Data Decryption", "Key Recovery"],
        "remediation_priority": 2,
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "example": "MD5, SHA1, DES, or RC4 usage"
    },

    # Insufficient Logging and Monitoring
    "CWE-778": {
        "name": "Insufficient Logging",
        "severity": "Medium",
        "cvss_base": 4.7,
        "nist_csf": ["DE.CM-01", "DE.AE-02"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Accountability"],
        "risk_keywords": ["Incident Detection Failure", "Forensic Limitations"],
        "remediation_priority": 3,
        "owasp_category": "A09:2021 – Security Logging and Monitoring Failures",
        "example": "Missing audit logs, insufficient event retention"
    },

    # Security Misconfiguration
    "CWE-16": {
        "name": "Configuration",
        "severity": "High",
        "cvss_base": 7.5,
        "nist_csf": ["PR.PS-01", "GV.RM-01"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Confidentiality", "Integrity"],
        "risk_keywords": ["Privilege Escalation", "Information Disclosure"],
        "remediation_priority": 2,
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "example": "Default credentials, unnecessary services enabled"
    },

    # Buffer Overflow
    "CWE-120": {
        "name": "Buffer Copy without Checking Size of Input",
        "severity": "High",
        "cvss_base": 8.6,
        "nist_csf": ["PR.PS-02", "PR.DS-01"],
        "attack_vectors": ["LOCAL", "NETWORK"],
        "impact_types": ["Confidentiality", "Integrity", "Availability"],
        "risk_keywords": ["Remote Code Execution", "Memory Corruption"],
        "remediation_priority": 1,
        "owasp_category": "N/A",
        "example": "strcpy, sprintf without bounds checking"
    },

    # Path Traversal
    "CWE-22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory",
        "severity": "High",
        "cvss_base": 7.5,
        "nist_csf": ["PR.DS-01", "PR.AA-05"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Confidentiality"],
        "risk_keywords": ["Unauthorized File Access", "Source Code Disclosure"],
        "remediation_priority": 2,
        "owasp_category": "A01:2021 – Broken Access Control",
        "example": "Unsanitized file paths: ../../etc/passwd"
    },

    # Null Pointer Dereference
    "CWE-476": {
        "name": "Null Pointer Dereference",
        "severity": "Medium",
        "cvss_base": 5.5,
        "nist_csf": ["PR.PS-02", "PR.IP-1"],
        "attack_vectors": ["NETWORK", "LOCAL"],
        "impact_types": ["Availability"],
        "risk_keywords": ["Denial of Service", "Application Crash"],
        "remediation_priority": 3,
        "owasp_category": "N/A",
        "example": "Unchecked null values causing crashes"
    },

    # Race Condition
    "CWE-362": {
        "name": "Concurrent Execution using Shared Resource with Improper Synchronization",
        "severity": "Medium",
        "cvss_base": 5.9,
        "nist_csf": ["PR.PS-01", "PR.PS-02"],
        "attack_vectors": ["LOCAL"],
        "impact_types": ["Integrity"],
        "risk_keywords": ["Data Corruption", "Logic Errors"],
        "remediation_priority": 3,
        "owasp_category": "N/A",
        "example": "Unsynchronized access to shared data structures"
    },

    # Command Injection
    "CWE-78": {
        "name": "Improper Neutralization of Special Elements used in an OS Command",
        "severity": "Critical",
        "cvss_base": 9.8,
        "nist_csf": ["PR.DS-01", "PR.PS-01"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Confidentiality", "Integrity", "Availability"],
        "risk_keywords": ["Remote Code Execution", "System Compromise"],
        "remediation_priority": 1,
        "owasp_category": "A03:2021 – Injection",
        "example": "Unvalidated shell commands: os.system(user_input)"
    },

    # LDAP Injection
    "CWE-90": {
        "name": "Improper Neutralization of Special Elements used in an LDAP Query",
        "severity": "High",
        "cvss_base": 7.5,
        "nist_csf": ["PR.DS-01", "PR.PS-01"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Confidentiality"],
        "risk_keywords": ["Directory Disclosure", "Authentication Bypass"],
        "remediation_priority": 2,
        "owasp_category": "A03:2021 – Injection",
        "example": "Unsanitized LDAP filters"
    },

    # Server-Side Request Forgery (SSRF)
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": "High",
        "cvss_base": 8.6,
        "nist_csf": ["PR.DS-01", "PR.AA-05"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Confidentiality", "Integrity"],
        "risk_keywords": ["Internal Resource Access", "Port Scanning"],
        "remediation_priority": 2,
        "owasp_category": "A10:2021 – Server-Side Request Forgery (SSRF)",
        "example": "Unvalidated URL parameters in HTTP requests"
    },

    # Open Redirect
    "CWE-601": {
        "name": "URL Redirection to Untrusted Site",
        "severity": "Medium",
        "cvss_base": 6.1,
        "nist_csf": ["PR.DS-01", "PR.AA-05"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Integrity"],
        "risk_keywords": ["Phishing", "Credential Theft"],
        "remediation_priority": 3,
        "owasp_category": "A01:2021 – Broken Access Control",
        "example": "Unvalidated redirect parameters"
    },

    # Insufficient Input Validation
    "CWE-20": {
        "name": "Improper Input Validation",
        "severity": "High",
        "cvss_base": 7.5,
        "nist_csf": ["PR.DS-01", "PR.PS-01"],
        "attack_vectors": ["NETWORK"],
        "impact_types": ["Confidentiality", "Integrity", "Availability"],
        "risk_keywords": ["Injection Attacks", "Buffer Overflow"],
        "remediation_priority": 2,
        "owasp_category": "A03:2021 – Injection",
        "example": "Missing whitelist validation, trusting user input"
    },
}

# ──────────────────────────────────────────────────────────────────
# CVSS Severity Mapping
# ──────────────────────────────────────────────────────────────────

CVSS_SEVERITY_MAP = {
    "Critical": {"min": 9.0, "max": 10.0, "priority": 1, "response_time": "1 hour"},
    "High": {"min": 7.0, "max": 8.9, "priority": 2, "response_time": "1 day"},
    "Medium": {"min": 4.0, "max": 6.9, "priority": 3, "response_time": "1 week"},
    "Low": {"min": 0.1, "max": 3.9, "priority": 4, "response_time": "1 month"},
}

# ──────────────────────────────────────────────────────────────────
# SonarQube Rule → CWE Mappings
# ──────────────────────────────────────────────────────────────────

SONARQUBE_RULE_TO_CWE = {
    "java:S2077": "CWE-89",      # SQL Injection
    "java:S3649": "CWE-89",      # SQL Injection
    "java:S5131": "CWE-79",      # XSS
    "java:S2755": "CWE-611",     # XXE
    "java:S4502": "CWE-352",     # CSRF
    "java:S2076": "CWE-78",      # Command Injection
    "java:S1948": "CWE-502",     # Deserialization
    "java:S2068": "CWE-798",     # Hardcoded Credential
    "java:S6437": "CWE-798",     # Hardcoded Secret
    "java:S5542": "CWE-327",     # Weak Crypto
    "java:S5547": "CWE-327",     # Weak Cipher
    "java:S2278": "CWE-327",     # DES Cipher
    "java:S4790": "CWE-327",     # Weak Hash
    "java:S106": "CWE-778",      # Insufficient Logging
    "javascript:S1821": "CWE-79", # XSS in JS
    "python:S5542": "CWE-327",   # Weak Crypto in Python
}

# ──────────────────────────────────────────────────────────────────
# NIST CSF 2.0 Categories Mapping
# ──────────────────────────────────────────────────────────────────

NIST_CSF_CATEGORIES = {
    "GV.OC": "Organizational Context",
    "GV.RM": "Risk Management Strategy",
    "GV.RR": "Roles, Responsibilities, and Authorities",
    "GV.PO": "Policy",
    "GV.OV": "Oversight",
    "GV.SC": "Supply Chain Risk Management",
    "ID.AM": "Asset Management",
    "ID.RA": "Risk Assessment",
    "ID.IM": "Improvement",
    "PR.AA": "Identity Management, Authentication, and Access Control",
    "PR.AT": "Awareness and Training",
    "PR.DS": "Data Security",
    "PR.PS": "Platform Security",
    "PR.IR": "Technology Infrastructure Resilience",
    "DE.CM": "Continuous Monitoring",
    "DE.AE": "Adverse Event Analysis",
    "RS.MA": "Incident Management",
    "RC.CO": "Coordination",
    "RC.IM": "Improvements",
}

# ──────────────────────────────────────────────────────────────────
# NIST CWE Attack Patterns
# ──────────────────────────────────────────────────────────────────

ATTACK_PATTERNS = {
    "Remote Code Execution": {
        "likelihood": "High",
        "impact": "Critical",
        "cwes": ["CWE-89", "CWE-78", "CWE-611", "CWE-502"],
    },
    "Data Leakage": {
        "likelihood": "High",
        "impact": "Critical",
        "cwes": ["CWE-89", "CWE-22", "CWE-639"],
    },
    "Unauthorized Access": {
        "likelihood": "High",
        "impact": "High",
        "cwes": ["CWE-287", "CWE-639", "CWE-798"],
    },
    "Session Hijacking": {
        "likelihood": "Medium",
        "impact": "High",
        "cwes": ["CWE-79", "CWE-352"],
    },
    "Privilege Escalation": {
        "likelihood": "High",
        "impact": "Critical",
        "cwes": ["CWE-639", "CWE-16"],
    },
    "Denial of Service": {
        "likelihood": "Medium",
        "impact": "High",
        "cwes": ["CWE-476", "CWE-611"],
    },
    "Logic Bypass": {
        "likelihood": "High",
        "impact": "High",
        "cwes": ["CWE-352", "CWE-601"],
    },
}

# ──────────────────────────────────────────────────────────────────
# Helper Functions
# ──────────────────────────────────────────────────────────────────

def get_cwe_info(cwe_id):
    """Retrieve CWE information by ID."""
    return CWE_DATABASE.get(cwe_id, None)


def get_severity_level(cvss_score):
    """Map CVSS score to severity level."""
    for severity, ranges in CVSS_SEVERITY_MAP.items():
        if ranges["min"] <= cvss_score <= ranges["max"]:
            return severity
    return "Unknown"


def map_sonarqube_rule_to_cwe(rule_key):
    """Map SonarQube rule key to CWE ID."""
    return SONARQUBE_RULE_TO_CWE.get(rule_key, None)


def get_attack_patterns_for_cwe(cwe_id):
    """Get applicable attack patterns for a CWE ID."""
    patterns = []
    for pattern_name, pattern_data in ATTACK_PATTERNS.items():
        if cwe_id in pattern_data.get("cwes", []):
            patterns.append(pattern_name)
    return patterns


def get_nist_csf_full_name(control_id):
    """Get full name of NIST CSF control."""
    return NIST_CSF_CATEGORIES.get(control_id, control_id)


def calculate_remediation_priority(cwe_severity, cwe_priority):
    """Calculate overall remediation priority (1=highest, 4=lowest)."""
    severity_priority = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4,
    }
    return min(severity_priority.get(cwe_severity, 4), cwe_priority)


if __name__ == "__main__":
    # Example usage
    print("CWE-89 Info:", get_cwe_info("CWE-89"))
    print("CVSS 8.5 Severity:", get_severity_level(8.5))
    print("SonarQube java:S2077 maps to:", map_sonarqube_rule_to_cwe("java:S2077"))
    print("Attack patterns for CWE-79:", get_attack_patterns_for_cwe("CWE-79"))
