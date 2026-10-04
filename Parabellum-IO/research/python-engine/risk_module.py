"""
risk_module.py
==============
Cross-references SonarQube findings with CWE database to assign standardized
risk scores, severity levels, and attack vectors for NIST-aligned compliance.

Features:
  - CWE mapping and risk scoring
  - NIST CSF alignment
  - Attack vector analysis
  - Risk impact summary generation
  - Compliance policy enforcement
"""

import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from cwe_database import (
    CWE_DATABASE, CVSS_SEVERITY_MAP, SONARQUBE_RULE_TO_CWE,
    get_cwe_info, get_severity_level, get_attack_patterns_for_cwe,
    ATTACK_PATTERNS, calculate_remediation_priority
)


class RiskScorer:
    """Assigns risk scores based on vulnerability characteristics."""
    
    def __init__(self):
        # Modifiers for risk scoring
        self.severity_multiplier = {
            "Critical": 4.0,
            "High": 2.0,
            "Medium": 1.0,
            "Low": 0.3
        }
        
        self.type_multiplier = {
            "VULNERABILITY": 3.0,
            "SECURITY_HOTSPOT": 2.5,
            "BUG": 1.5,
            "CODE_SMELL": 0.5
        }
        
        self.attack_vector_multiplier = {
            "NETWORK": 2.0,
            "APPLICATION": 1.5,
            "LOCAL": 0.8,
            "PHYSICAL": 0.3
        }
    
    def compute_risk_score(self, 
                          cve_severity: str, 
                          cvss_base: float,
                          issue_type: str,
                          attack_vectors: List[str]) -> float:
        """
        Compute a composite risk score (0-100).
        
        Args:
            cve_severity: Severity level (Critical, High, Medium, Low)
            cvss_base: CVSS base score
            issue_type: SonarQube issue type
            attack_vectors: List of attack vectors (NETWORK, LOCAL, etc.)
            
        Returns:
            Risk score 0-100
        """
        # Base: CVSS score (0-10) * 10
        base_score = cvss_base * 10
        
        # Severity multiplier
        severity_mult = self.severity_multiplier.get(cve_severity, 1.0)
        
        # Type multiplier
        type_mult = self.type_multiplier.get(issue_type, 1.0)
        
        # Attack vector multiplier (use highest)
        attack_mult = max(
            [self.attack_vector_multiplier.get(av, 1.0) for av in attack_vectors],
            default=1.0
        )
        
        # Calculate score
        risk_score = (base_score * severity_mult * type_mult * attack_mult) / 10
        
        # Cap at 100
        return min(risk_score, 100.0)
    
    def normalize_score(self, raw_score: float) -> str:
        """Convert raw score to risk level."""
        if raw_score >= 80:
            return "Critical"
        elif raw_score >= 60:
            return "High"
        elif raw_score >= 40:
            return "Medium"
        elif raw_score >= 20:
            return "Low"
        else:
            return "Minimal"


class VulnerabilityAnalyzer:
    """Analyzes SonarQube findings and maps them to vulnerabilities."""
    
    def __init__(self):
        self.risk_scorer = RiskScorer()
    
    def analyze_finding(self, sonarcube_issue: Dict) -> Dict:
        """
        Analyze a single SonarQube finding and produce risk metadata.
        
        Args:
            sonarqube_issue: Standardized SonarQube issue dict
            
        Returns:
            Enriched finding with risk analysis
        """
        # Map rule to CWE if possible
        cwe_id = SONARQUBE_RULE_TO_CWE.get(sonarcube_issue.get("rule"))
        cwe_info = get_cwe_info(cwe_id) if cwe_id else None
        
        # Fallback: guess CWE from message/type
        if not cwe_id and sonarcube_issue.get("type") == "VULNERABILITY":
            cwe_id = self._guess_cwe_from_context(sonarcube_issue)
            cwe_info = get_cwe_info(cwe_id) if cwe_id else None
        
        # Extract risk data from CWE or defaults
        if cwe_info:
            severity = cwe_info.get("severity", sonarcube_issue.get("severity", "Medium"))
            cvss_base = cwe_info.get("cvss_base", self._estimate_cvss(severity))
            attack_vectors = cwe_info.get("attack_vectors", ["NETWORK"])
            risk_keywords = cwe_info.get("risk_keywords", [])
        else:
            severity = sonarcube_issue.get("severity", "Medium")
            cvss_base = self._estimate_cvss(severity)
            attack_vectors = ["NETWORK"]
            risk_keywords = self._extract_risk_keywords(sonarcube_issue)
        
        # Compute risk score
        risk_score = self.risk_scorer.compute_risk_score(
            severity,
            cvss_base,
            sonarcube_issue.get("type", "CODE_SMELL"),
            attack_vectors
        )
        risk_level = self.risk_scorer.normalize_score(risk_score)
        
        # Get attack patterns
        attack_patterns = get_attack_patterns_for_cwe(cwe_id) if cwe_id else []
        
        # Generate risk impact summary
        impact_summary = self._generate_impact_summary(
            sonarcube_issue,
            cwe_info,
            attack_patterns
        )
        
        # NIST controls
        nist_controls = cwe_info.get("nist_csf", []) if cwe_info else self._guess_nist_controls(sonarcube_issue)
        
        return {
            "original_issue": sonarcube_issue,
            "cwe_mapping": {
                "cwe_id": cwe_id,
                "cwe_name": cwe_info.get("name") if cwe_info else "Unknown",
                "owasp_category": cwe_info.get("owasp_category") if cwe_info else "N/A"
            },
            "risk_assessment": {
                "severity": severity,
                "cvss_score": cvss_base,
                "attack_vectors": attack_vectors,
                "risk_score": round(risk_score, 2),
                "risk_level": risk_level,
                "remediation_priority": calculate_remediation_priority(
                    severity, 
                    cwe_info.get("remediation_priority", 4) if cwe_info else 4
                ),
                "response_time": CVSS_SEVERITY_MAP.get(severity, {}).get("response_time", "1 month")
            },
            "attack_analysis": {
                "applicable_patterns": attack_patterns,
                "attack_types": self._get_attack_types_for_patterns(attack_patterns),
                "impact_summary": impact_summary
            },
            "compliance": {
                "nist_csf_controls": nist_controls,
                "policy_violations": self._check_policy_violations(risk_level, sonarcube_issue)
            },
            "remediation": {
                "guidance": cwe_info.get("remediation_guidance", self._default_remediation(sonarcube_issue)) if cwe_info else self._default_remediation(sonarcube_issue),
                "effort_estimate": sonarcube_issue.get("effort", "5min"),
                "technical_debt": sonarcube_issue.get("debt", "10min")
            },
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def analyze_findings_batch(self, findings: List[Dict]) -> Dict:
        """
        Analyze a batch of findings and produce aggregate metrics.
        
        Returns:
            {
              "individual_analyses": [...],
              "aggregate_metrics": {...},
              "summary": {...}
            }
        """
        analyses = [self.analyze_finding(f) for f in findings]
        
        # Compute aggregates
        severity_counts = {}
        risk_level_counts = {}
        total_risk_score = 0
        
        for analysis in analyses:
            severity = analysis["risk_assessment"]["severity"]
            risk_level = analysis["risk_assessment"]["risk_level"]
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            risk_level_counts[risk_level] = risk_level_counts.get(risk_level, 0) + 1
            total_risk_score += analysis["risk_assessment"]["risk_score"]
        
        avg_risk_score = total_risk_score / len(analyses) if analyses else 0
        
        critical_issues = [a for a in analyses if a["risk_assessment"]["risk_level"] == "Critical"]
        high_issues = [a for a in analyses if a["risk_assessment"]["risk_level"] == "High"]
        
        return {
            "total_findings": len(analyses),
            "individual_analyses": analyses,
            "aggregate_metrics": {
                "severity_distribution": severity_counts,
                "risk_level_distribution": risk_level_counts,
                "average_risk_score": round(avg_risk_score, 2),
                "critical_count": len(critical_issues),
                "high_count": len(high_issues),
                "estimated_remediation_effort": self._estimate_total_effort(analyses)
            },
            "overall_risk_assessment": {
                "portfolio_risk_level": "Critical" if critical_issues else "High" if high_issues else "Medium",
                "requires_immediate_action": len(critical_issues) > 0,
                "policy_compliance": "FAIL" if critical_issues else "PASS" if len(high_issues) < 5 else "WARNING"
            }
        }
    
    def _estimate_cvss(self, severity: str) -> float:
        """Estimate CVSS from severity level."""
        mapping = {
            "Critical": 9.5,
            "High": 7.5,
            "Medium": 5.5,
            "Low": 2.5
        }
        return mapping.get(severity, 5.0)
    
    def _guess_cwe_from_context(self, issue: Dict) -> Optional[str]:
        """Try to guess CWE from issue message and type."""
        message = (issue.get("message", "") + " " + issue.get("rule", "")).lower()
        
        keyword_cwe_map = {
            "sql": "CWE-89",
            "xss": "CWE-79",
            "csrf": "CWE-352",
            "xxe": "CWE-611",
            "auth": "CWE-287",
            "crypto": "CWE-327",
            "harden": "CWE-798",
            "injection": "CWE-78",
            "path": "CWE-22",
            "ssrf": "CWE-918",
            "deserialization": "CWE-502"
        }
        
        for keyword, cwe in keyword_cwe_map.items():
            if keyword in message:
                return cwe
        
        return None
    
    def _extract_risk_keywords(self, issue: Dict) -> List[str]:
        """Extract risk keywords from issue."""
        keywords = []
        message = (issue.get("message", "") + " " + issue.get("rule", "")).lower()
        
        risk_keywords_list = [
            "injection", "sql", "xss", "csrf", "xxe", 
            "auth", "crypto", "hardcod", "path traversal", "ssrf"
        ]
        
        for keyword in risk_keywords_list:
            if keyword in message:
                keywords.append(keyword)
        
        return keywords
    
    def _generate_impact_summary(self, 
                                issue: Dict, 
                                cwe_info: Optional[Dict],
                                attack_patterns: List[str]) -> str:
        """Generate a human-readable impact summary."""
        parts = []
        
        # Main impact
        if cwe_info:
            impact_types = cwe_info.get("impact_types", [])
            if impact_types:
                parts.append(f"Impacts: {', '.join(impact_types)}")
            
            risk_keywords = cwe_info.get("risk_keywords", [])
            if risk_keywords:
                parts.append(f"Risk: {' and '.join(risk_keywords)}")
        
        # Attack patterns
        if attack_patterns:
            parts.append(f"Attack Vectors: {', '.join(attack_patterns)}")
        
        if not parts:
            parts.append(f"Issue: {issue.get('message', 'Unknown vulnerability')}")
        
        return " → ".join(parts)
    
    def _get_attack_types_for_patterns(self, patterns: List[str]) -> List[str]:
        """Get attack types from patterns."""
        attack_types = []
        for pattern in patterns:
            pattern_data = ATTACK_PATTERNS.get(pattern, {})
            if pattern_data:
                attack_types.append({
                    "type": pattern,
                    "likelihood": pattern_data.get("likelihood"),
                    "impact": pattern_data.get("impact")
                })
        return attack_types
    
    def _guess_nist_controls(self, issue: Dict) -> List[str]:
        """Guess NIST controls from issue type."""
        type_control_map = {
            "VULNERABILITY": ["PR.DS-01", "PR.AA-01"],
            "SECURITY_HOTSPOT": ["PR.DS-01", "DE.CM-01"],
            "BUG": ["PR.PS-01"],
            "CODE_SMELL": ["PR.IP-1"]
        }
        issue_type = issue.get("type", "CODE_SMELL")
        return type_control_map.get(issue_type, ["GV.RM-01"])
    
    def _check_policy_violations(self, risk_level: str, issue: Dict) -> List[str]:
        """Check against policy thresholds."""
        violations = []
        
        if risk_level in ["Critical", "High"]:
            violations.append(f"High-risk vulnerability present (Risk Level: {risk_level})")
        
        if issue.get("type") == "VULNERABILITY" and risk_level != "Low":
            violations.append("Unresolved security vulnerability")
        
        if issue.get("severity") == "Critical":
            violations.append("Critical severity finding")
        
        return violations
    
    def _default_remediation(self, issue: Dict) -> str:
        """Provide generic remediation guidance."""
        issue_type = issue.get("type", "")
        
        guidance_map = {
            "VULNERABILITY": "1) Review SonarQube rule for specific guidance\n2) Apply secure coding practices\n3) Conduct security testing\n4) Obtain security review approval",
            "SECURITY_HOTSPOT": "1) Verify implementation matches security guidelines\n2) Document security design decisions\n3) Obtain InfoSec approval",
            "BUG": "1) Identify root cause\n2) Implement fix\n3) Add unit tests\n4) Validate fix",
            "CODE_SMELL": "1) Refactor code for clarity\n2) Follow coding standards\n3) Improve maintainability"
        }
        
        return guidance_map.get(issue_type, "Review issue and implement appropriate remediation")
    
    def _estimate_total_effort(self, analyses: List[Dict]) -> str:
        """Estimate total remediation effort."""
        effort_hours = 0
        effort_mapping = {
            "5min": 0.08,
            "10min": 0.17,
            "20min": 0.33,
            "30min": 0.5,
            "1h": 1,
            "2h": 2,
            "3h": 3,
            "4h": 4,
            "5h": 5,
            "8h": 8
        }
        
        for analysis in analyses:
            effort = analysis.get("remediation", {}).get("effort_estimate", "5min")
            effort_hours += effort_mapping.get(effort, 0.5)
        
        if effort_hours < 1:
            return f"< 1 hour"
        elif effort_hours < 8:
            return f"{int(effort_hours)} hours"
        else:
            days = effort_hours / 8
            return f"{int(days)} days"


if __name__ == "__main__":
    # Example usage
    analyzer = VulnerabilityAnalyzer()
    
    example_issue = {
        "key": "AVxxx",
        "component": "project:test.java",
        "rule": "java:S2077",
        "severity": "CRITICAL",
        "type": "VULNERABILITY",
        "message": "SQL injection vulnerability detected",
        "effort": "1h",
        "debt": "30min"
    }
    
    analysis = analyzer.analyze_finding(example_issue)
    print(json.dumps(analysis, indent=2))
