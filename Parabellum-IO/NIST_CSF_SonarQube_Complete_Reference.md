# NIST CSF 2.0 & SonarQube Rules - Complete Reference Guide
## For Parabellum IO - GRC Compliance Framework

---

## Table of Contents
1. [NIST CSF 2.0 Framework Overview](#nist-csf-20-framework-overview)
2. [Complete NIST CSF 2.0 Structure](#complete-nist-csf-20-structure)
3. [PR.PS-01 Detailed Explanation](#prps-01-detailed-explanation)
4. [All NIST CSF 2.0 Categories](#all-nist-csf-20-categories)
5. [SonarQube Rules Explanation](#sonarqube-rules-explanation)
6. [Kubernetes Rules Explanation](#kubernetes-rules-explanation)

---

## NIST CSF 2.0 Framework Overview

### Key Statistics
- **6 Functions** (up from 5 in v1.1)
- **22 Categories** (down from 23 in v1.1)
- **106 Subcategories** (down from 108 in v1.1)
- Released: **February 26, 2024**
- First major update in **10 years** (since 2014)

### Major Changes from v1.1 to v2.0
1. **New GOVERN Function** - Added as 6th function, emphasizing governance
2. **Supply Chain Focus** - Enhanced guidance on third-party risk management
3. **Broader Scope** - Now applies to ALL organizations, not just critical infrastructure
4. **Restructured Categories** - Many merged, renamed, or reorganized

---

## Complete NIST CSF 2.0 Structure

### 6 Core Functions

#### 1. **GOVERN (GV)** - NEW in v2.0
**Purpose:** Establishes cybersecurity governance, risk management strategy, and roles/responsibilities

**Categories:**
- **GV.OC** - Organizational Context
- **GV.RM** - Risk Management Strategy  
- **GV.RR** - Roles, Responsibilities, and Authorities
- **GV.PO** - Policy
- **GV.OV** - Oversight
- **GV.SC** - Cybersecurity Supply Chain Risk Management

**Total Subcategories:** ~30 (nearly 30% of entire framework)

---

#### 2. **IDENTIFY (ID)**
**Purpose:** Understand organizational assets, business environment, and cybersecurity risks

**Categories:**
- **ID.AM** - Asset Management
- **ID.RA** - Risk Assessment  
- **ID.IM** - Improvement

**Key Subcategories:**
- ID.AM-01: Inventories of hardware managed by the organization are maintained
- ID.AM-02: Inventories of software, services, and systems managed by the organization are maintained
- ID.AM-03: Representations of the organization's authorized network communication and internal and external network data flows are maintained
- ID.AM-05: Resources are prioritized based on classification, criticality, and business value
- ID.RA-01: Vulnerabilities in assets are identified, validated, and recorded
- ID.RA-02: Cyber threat intelligence is received from information sharing forums and sources
- ID.RA-03: Internal and external threats to the organization are identified and recorded
- ID.RA-04: Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded
- ID.RA-05: Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response decisions
- ID.RA-06: Risk responses are chosen, prioritized, planned, tracked, and communicated
- ID.RA-07: Changes and exceptions are managed, assessed for risk impact, recorded, and tracked
- ID.RA-08: Processes for receiving, analyzing, and responding to vulnerability disclosures are established
- ID.IM-01: Improvements are identified from execution of operational cybersecurity activities, evaluation processes, incident response and recovery activities, and other sources

---

#### 3. **PROTECT (PR)**
**Purpose:** Implement safeguards to ensure delivery of critical services

**Categories:**
- **PR.AA** - Identity Management, Authentication, and Access Control
- **PR.AT** - Awareness and Training
- **PR.DS** - Data Security
- **PR.PS** - Platform Security ← **YOUR MAPPING (PR.PS-01)**
- **PR.IR** - Technology Infrastructure Resilience

**Key Subcategories:**

**PR.AA (Identity & Access):**
- PR.AA-01: Identities and credentials for authorized users, services, and hardware are managed
- PR.AA-02: Identities are proofed and bound to credentials based on risk
- PR.AA-03: Users, services, and hardware are authenticated
- PR.AA-04: Identity assertions are protected, conveyed, and verified
- PR.AA-05: Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed
- PR.AA-06: Physical access to assets is managed, monitored, and enforced commensurate with risk

**PR.AT (Awareness & Training):**
- PR.AT-01: Personnel are provided with awareness and training
- PR.AT-02: Individuals in specialized roles are provided with awareness and training

**PR.DS (Data Security):**
- PR.DS-01: The confidentiality, integrity, and availability of data-at-rest is protected
- PR.DS-02: The confidentiality, integrity, and availability of data-in-transit is protected
- PR.DS-03: Data is managed throughout its life cycle
- PR.DS-04: The confidentiality, integrity, and availability of data-in-use is protected ← **NEW**
- PR.DS-05: Backups of data are conducted, protected, maintained, and tested
- PR.DS-10: The confidentiality, integrity, and availability of data-in-use are protected
- PR.DS-11: Personally identifiable information (PII) is managed commensurate with risk

**PR.PS (Platform Security):**
- **PR.PS-01**: Configuration management practices are established and applied ← **YOUR CLAUSE**
- **PR.PS-02**: Software is maintained, replaced, and removed commensurate with risk
- **PR.PS-03**: Hardware is maintained, replaced, and removed commensurate with risk
- **PR.PS-04**: Log records are generated and made available for continuous monitoring
- **PR.PS-05**: Installation and execution of unauthorized software are prevented
- **PR.PS-06**: Secure software development practices are integrated

**PR.IR (Infrastructure Resilience):**
- PR.IR-01: Networks and environments are protected from unauthorized logical access
- PR.IR-02: The organization's technology assets are protected from environmental threats
- PR.IR-03: Mechanisms are implemented to achieve resilience requirements
- PR.IR-04: Adequate resource capacity to ensure availability is maintained

---

#### 4. **DETECT (DE)**
**Purpose:** Identify cybersecurity events in a timely manner

**Categories:**
- **DE.CM** - Continuous Monitoring
- **DE.AE** - Adverse Event Analysis

**Key Subcategories:**
- DE.CM-01: Networks and network services are monitored to find potentially adverse events
- DE.CM-02: The physical environment is monitored to find potentially adverse events
- DE.CM-03: Personnel activity and technology usage are monitored to find potentially adverse events
- DE.CM-06: External service provider activities and services are monitored to find potentially adverse events
- DE.CM-09: Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events
- DE.AE-01: Potentially adverse events are analyzed to better understand associated activities
- DE.AE-02: Potentially adverse events are analyzed to understand attack targets and methods
- DE.AE-03: Information is correlated from multiple sources
- DE.AE-04: The estimated impact and scope of adverse events are understood
- DE.AE-06: Information on adverse events is provided to authorized staff and tools
- DE.AE-07: Cyber threat intelligence and other contextual information are integrated into the analysis
- DE.AE-08: Incidents are declared when adverse events meet the defined incident criteria

---

#### 5. **RESPOND (RS)**
**Purpose:** Take action regarding a detected cybersecurity incident

**Categories:**
- **RS.MA** - Incident Management
- **RS.AN** - Incident Analysis
- **RS.MI** - Incident Mitigation

**Key Subcategories:**
- RS.MA-01: The incident response plan is executed in coordination with relevant parties once an incident is declared
- RS.MA-02: Incident reports are triaged and validated
- RS.MA-03: Incidents are categorized and prioritized
- RS.MA-04: Incidents are escalated or elevated as needed
- RS.MA-05: The criteria for initiating incident recovery are applied
- RS.AN-01: Incident information and context are shared with relevant stakeholders
- RS.AN-03: Analysis is performed to establish what has taken place during an incident and the root cause of the incident
- RS.AN-06: Actions performed during an incident are recorded, and the records' integrity and provenance are preserved
- RS.MI-01: Incidents are contained
- RS.MI-02: Incidents are eradicated

---

#### 6. **RECOVER (RC)**
**Purpose:** Restore capabilities or services impaired due to a cybersecurity incident

**Categories:**
- **RC.RP** - Incident Recovery Plan Execution
- **RC.CO** - Incident Recovery Communication

**Key Subcategories:**
- RC.RP-01: The recovery portion of the incident response plan is executed once initiated from the incident response process
- RC.RP-02: Recovery actions are selected, scoped, prioritized, and performed
- RC.RP-03: The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed
- RC.RP-04: Critical mission functions and cybersecurity risk management are considered to establish post-incident operational norms
- RC.RP-05: The integrity of restored assets is verified
- RC.RP-06: Criteria for determining the end of incident recovery are defined and applied
- RC.CO-01: Public relations are managed
- RC.CO-02: Reputation is repaired
- RC.CO-03: Recovery activities and progress are communicated

---

## PR.PS-01 Detailed Explanation

### Full Clause Text
**"Configuration management practices are established and applied"**

### What It Means
This subcategory ensures that organizations maintain secure and controlled IT configurations through:
- Hardened baselines for systems
- Change control processes
- Least functionality principle (only enable what's necessary)
- Regular configuration audits

### What This Clause Incorporates (from NIST CSF v1.1)
PR.PS-01 consolidates these FOUR previous subcategories:
1. **PR.IP-1**: Baseline configuration with security principles
2. **PR.IP-3**: Configuration change control processes
3. **PR.PT-2**: Removable media protection
4. **PR.PT-3**: Principle of least functionality

### Implementation Examples from NIST

**Ex1:** Establish, test, deploy, and maintain hardened baselines that enforce the organization's cybersecurity policies and provide only essential capabilities (principle of least functionality)

**Ex2:** Review all default configuration settings that may potentially impact cybersecurity when installing or updating technology platforms

**Ex3:** Manage baseline configurations for technology platforms throughout their development and useful life

**Ex4:** Retain previous secure configurations for  rollback purposes

**Ex5:** Use automated configuration assessment tools to verify compliance with secure baselines

**Ex6:** Apply secure configurations for all system components, including applications, databases, servers, network devices, and cloud services

### How Your System Maps to PR.PS-01

Based on your screenshot, here's what maps:

| **Severity** | **Type** | **Issue** | **Why It Maps to PR.PS-01** |
|---|---|---|---|
| MAJOR | VULNERABILITY | Bind service account to RBAC | Enforces least privilege configuration |
| MAJOR | CODE_SMELL | Specify storage request | Ensures resource limits are configured |
| MAJOR | CODE_SMELL | Specify CPU request | Ensures resource limits are configured |
| MAJOR | VULNERABILITY | Specify memory limit | Prevents resource exhaustion attacks |
| MAJOR | CODE_SMELL | Specify memory request | Baseline resource configuration |
| MAJOR | CODE_SMELL | Use specific version tag | Prevents configuration drift from "latest" |
| BLOCKER | BUG | Use try-with-resources (java:S2095) | Proper resource management configuration |

**All of these** relate to **configuration management** because they enforce:
- Secure defaults (RBAC, resource limits)
- Change control (version tags, not "latest")
- Least functionality (memory/CPU limits prevent abuse)
- Baseline standards (consistent resource requests)

---

## All NIST CSF 2.0 Categories

### Complete List with Subcategory Counts

| **Function** | **Category Code** | **Category Name** | **# of Subcategories** |
|---|---|---|---|
| **GOVERN** | GV.OC | Organizational Context | 5 |
| | GV.RM | Risk Management Strategy | 7 |
| | GV.RR | Roles, Responsibilities, and Authorities | 3 |
| | GV.PO | Policy | 5 |
| | GV.OV | Oversight | 3 |
| | GV.SC | Cybersecurity Supply Chain Risk Management | 10 |
| **IDENTIFY** | ID.AM | Asset Management | 7 |
| | ID.RA | Risk Assessment | 10 |
| | ID.IM | Improvement | 2 |
| **PROTECT** | PR.AA | Identity Management, Authentication, Access Control | 6 |
| | PR.AT | Awareness and Training | 2 |
| | PR.DS | Data Security | 11 |
| | PR.PS | Platform Security | 6 |
| | PR.IR | Technology Infrastructure Resilience | 4 |
| **DETECT** | DE.CM | Continuous Monitoring | 9 |
| | DE.AE | Adverse Event Analysis | 8 |
| **RESPOND** | RS.MA | Incident Management | 5 |
| | RS.AN | Incident Analysis | 7 |
| | RS.MI | Incident Mitigation | 2 |
| **RECOVER** | RC.RP | Incident Recovery Plan Execution | 6 |
| | RC.CO | Incident Recovery Communication | 3 |

**TOTAL: 22 Categories, 106 Subcategories**

---

## SonarQube Rules Explanation

### Rule Naming Convention
SonarQube rules follow the pattern: `<language>:<rule_id>`

Examples:
- `java:S2095` → Java language, rule S2095
- `kubernetes:S6865` → Kubernetes configuration, rule S6865

### Total Number of SonarQube Rules

| **Language** | **Approximate # of Rules** |
|---|---|
| Java | 600+ rules |
| JavaScript/TypeScript | 300+ rules |
| Python | 300+ rules |
| C# | 400+ rules |
| Kubernetes/IaC | 100+ rules |
| **TOTAL** | **2000+ rules across all languages** |

---

### java:S2095 - Detailed Explanation

#### Rule Name
**"Resources should be closed"**

#### Category
- **Type:** BUG
- **Severity:** BLOCKER (highest)
- **Language:** Java

#### What It Does
Detects when `Closeable` or `AutoCloseable` resources (streams, connections, files) are opened but not properly closed, which causes **resource leaks**.

#### Why It's Critical
- **Memory Leaks:** Unclosed resources consume memory until garbage collection
- **File Handle Exhaustion:** Operating system has limited file handles
- **Database Connection Pool Depletion:** Unclosed DB connections exhaust the pool
- **Application Crashes:** Eventually leads to "Too many open files" errors
- **Performance Degradation:** Slows down application over time

#### Technical Details

**Affected Resource Types:**
- `FileInputStream`, `FileOutputStream`
- `BufferedReader`, `BufferedWriter`
- `Connection` (JDBC database connections)
- `Statement`, `PreparedStatement`, `ResultSet`
- `Socket`, `ServerSocket`
- `ZipInputStream`, `ZipOutputStream`
- Any class implementing `Closeable` or `AutoCloseable`

**Detection Scope:**
- Looks for resources opened in try blocks or method bodies
- Checks if `.close()` is called in `finally` blocks
- Validates try-with-resources statements

#### Code Examples

**❌ VIOLATION (What SonarQube Flags):**
```java
public void badExample() throws IOException {
    FileInputStream fis = new FileInputStream("file.txt");
    // Do something with fis
    // BUG: Resource never closed → memory leak!
}
```

**❌ VIOLATION (Unsafe Close):**
```java
public void unsafeClose() throws IOException {
    FileInputStream fis = new FileInputStream("file.txt");
    fis.close(); // If exception happens before this, never closed!
}
```

**✅ CORRECT (Try-Finally):**
```java
public void correctFinally() throws IOException {
    FileInputStream fis = null;
    try {
        fis = new FileInputStream("file.txt");
        // Use fis
    } finally {
        if (fis != null) {
            fis.close();
        }
    }
}
```

**✅ CORRECT (Try-With-Resources - BEST PRACTICE):**
```java
public void correctTryWithResources() throws IOException {
    try (FileInputStream fis = new FileInputStream("file.txt")) {
        // Use fis
    } // Automatically closed, even if exception occurs
}
```

**✅ CORRECT (Multiple Resources):**
```java
public void multipleResources() throws IOException, SQLException {
    try (
        Connection conn = DriverManager.getConnection(url);
        PreparedStatement stmt = conn.prepareStatement(sql);
        ResultSet rs = stmt.executeQuery()
    ) {
        // All three resources auto-closed in reverse order
    }
}
```

#### Real-World Impact in Your Screenshot

From your image, you have **BLOCKER** issues with java:S2095:
- `Use try-with-resources or close this "Connection" in a "finally" clause`
- `Use try-with-resources or close this "Statement" in a "finally" clause`
- `Use try-with-resources or close this "ZipInputStream" in a "finally" clause`
- `Use try-with-resources or close this "FileOutputStream" in a "finally" clause`
- `Use try-with-resources or close this "FileWriter" in a "finally" clause`

**Why These Are BLOCKERS:**
1. **Database Connections:** Unclosed connections exhaust connection pool → application can't query database
2. **File Streams:** Unclosed file handles → "Too many open files" error → server crash
3. **Zip Streams:** Memory not released → gradual memory exhaustion

#### How to Fix in Your Code

**Step 1:** Find all instances flagged by SonarQube

**Step 2:** Refactor to try-with-resources (Java 7+):
```java
// BEFORE (flagged by S2095)
Connection conn = DriverManager.getConnection(url);
Statement stmt = conn.createStatement();
// ... use statement
stmt.close();
conn.close();

// AFTER (compliant)
try (Connection conn = DriverManager.getConnection(url);
     Statement stmt = conn.createStatement()) {
    // ... use statement
} // Auto-closed automatically
```

**Step 3:** For legacy Java 6 code:
```java
Connection conn = null;
Statement stmt = null;
try {
    conn = DriverManager.getConnection(url);
    stmt = conn.createStatement();
    // ... use statement
} finally {
    if (stmt != null) try { stmt.close(); } catch (SQLException e) { /* log */ }
    if (conn != null) try { conn.close(); } catch (SQLException e) { /* log */ }
}
```

---

### Kubernetes Rules (from your screenshot)

#### kubernetes:S6865 - RBAC Service Account Binding
**Issue:** "Bind this resource's automounted service account to RBAC or disable service account automounting"

**Severity:** MAJOR  
**Type:** VULNERABILITY

**What It Means:**
- Kubernetes automatically mounts service account tokens into pods
- If not bound to Role-Based Access Control (RBAC), pods have excessive permissions
- **Security Risk:** Pod compromise = cluster-wide access

**How to Fix:**
```yaml
# Option 1: Bind to RBAC Role
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: my-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: my-binding
subjects:
- kind: ServiceAccount
  name: my-service-account
roleRef:
  kind: Role
  name: my-role
  apiGroup: rbac.authorization.k8s.io
```

```yaml
# Option 2: Disable automounting if not needed
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  automountServiceAccountToken: false
  containers:
  - name: app
    image: myapp:1.0
```

**Maps to NIST PR.PS-01:** Enforces least privilege configuration

---

#### kubernetes:S6897 / S6892 / S6873 - Resource Limits

**Issues:**
- S6897: "Specify a storage request for this container"
- S6892: "Specify a CPU request for this container"
- S6873: "Specify a memory request for this container"
- S6864: "Specify a memory limit for this container"

**Severity:** MAJOR  
**Type:** CODE_SMELL (S6897, S6892, S6873) / VULNERABILITY (S6864)

**What It Means:**
- Containers without resource limits can consume all node resources
- Can cause denial-of-service to other containers
- **Security Risk:** Resource exhaustion attack

**How to Fix:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
  - name: app
    image: myapp:1.0
    resources:
      requests:  # Minimum guaranteed resources
        memory: "64Mi"
        cpu: "250m"
        storage: "1Gi"  # For stateful workloads
      limits:  # Maximum allowed resources
        memory: "128Mi"
        cpu: "500m"
```

**Best Practices:**
- **Requests:** What container needs to run normally
- **Limits:** Maximum to prevent runaway consumption
- **Memory limits prevent OOM kills** of other pods
- **CPU limits prevent CPU starvation** of other workloads

**Maps to NIST PR.PS-01:** Baseline resource configuration management

---

#### kubernetes:S6596 - Container Image Versioning

**Issue:** "Use a specific version tag for the image instead of 'latest'"

**Severity:** MAJOR  
**Type:** CODE_SMELL

**What It Means:**
- Using `:latest` tag means unpredictable deployments
- Image content can change without manifest changing
- **Security Risk:** Malicious image update, configuration drift

**How to Fix:**
```yaml
# ❌ BAD
spec:
  containers:
  - name: app
    image: myapp:latest  # Unpredictable, changes without notice

# ✅ GOOD
spec:
  containers:
  - name: app
    image: myapp:1.2.3  # Immutable, reproducible
    # OR
    image: myapp@sha256:abc123...  # Even better: content-addressable
```

**Best Practices:**
- Use semantic versioning (1.2.3)
- Or use SHA256 digest for immutability
- Never use `:latest` in production

**Maps to NIST PR.PS-01:** Change control and configuration baseline

---

## Summary: How It All Connects

### Your GRC System Flow

1. **DevSecOps Tools Scan Code/Containers**
   - SonarQube finds: java:S2095 (unclosed resources)
   - Trivy/Anchore finds: kubernetes:S6865 (RBAC issues)

2. **Your Rule-Based Engine Maps to NIST**
   - java:S2095 → PR.PS-01 (Configuration Management)
   - kubernetes:S6865 → PR.PS-01 (Least Privilege Config)
   - kubernetes:S6864 → PR.PS-01 (Resource Baseline Config)

3. **Compliance Dashboard Shows**
   - **Clause:** PR.PS-01 - Configuration Management Practices
   - **Violations:** 15 issues (6 MAJOR, 5 BLOCKER)
   - **Compliance Score:** 85% (missing proper resource limits, try-with-resources)
   - **Remediation:** "Implement try-with-resources for all Closeable objects"

4. **RAG System Learns**
   - Stores: "java:S2095 in authentication module = always P0"
   - Learns: "kubernetes resource limits = frequently recurring issue"
   - Improves: "Next time, auto-suggest try-with-resources template"

---

## Quick Reference Tables

### NIST CSF 2.0 Functions
| Function | Code | Focus Area | # Categories |
|---|---|---|---|
| Govern | GV | Governance & Risk Strategy | 6 |
| Identify | ID | Asset & Risk Understanding | 3 |
| Protect | PR | Safeguards Implementation | 5 |
| Detect | DE | Event Detection | 2 |
| Respond | RS | Incident Response | 3 |
| Recover | RC | Recovery Operations | 2 |

### SonarQube Severity Levels
| Severity | Meaning | Priority |
|---|---|---|
| BLOCKER | Prevents deployment | Fix immediately |
| CRITICAL | High security risk | Fix within 24h |
| MAJOR | Significant issue | Fix within 1 week |
| MINOR | Quality/maintainability | Fix in sprint |
| INFO | Informational | Low priority |

### Common SonarQube Rule Prefixes
| Prefix | Language/Type |
|---|---|
| java:S | Java language rules |
| python:S | Python language rules |
| javascript:S | JavaScript rules |
| typescript:S | TypeScript rules |
| kubernetes:S | Kubernetes/container rules |
| docker:S | Dockerfile rules |
| terraform:S | Terraform IaC rules |

---

**Document Version:** 1.0  
**Last Updated:** January 2025  
**Prepared for:** Parabellum IO - Mid Evaluation Presentation
