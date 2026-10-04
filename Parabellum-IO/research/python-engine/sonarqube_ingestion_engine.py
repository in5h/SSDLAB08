"""
sonarqube_ingestion_engine.py
=============================
Monitors a directory for SonarQube JSON/YAML exports and manages versioning,
diffing, and tracking of resolved vs newly introduced technical debt.

Features:
  - Directory monitoring for SonarQube exports
  - JSON/YAML parsing support
  - Diff engine: new, resolved, unchanged findings
  - Local cache management (JSON-based)
  - Incremental ingestion tracking
"""

import json
import yaml
import os
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class SonarQubeIngestionCache:
    """Manages local cache of processed SonarQube findings."""
    
    def __init__(self, cache_dir: str = "./cache"):
        """
        Initialize cache directory.
        
        Args:
            cache_dir: Directory to store cached results
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_index = self._load_cache_index()
    
    def _load_cache_index(self) -> Dict:
        """Load the cache index file."""
        index_file = self.cache_dir / "index.json"
        if index_file.exists():
            with open(index_file, 'r') as f:
                return json.load(f)
        return {
            "last_processed": None,
            "cached_exports": {},
            "total_ingestions": 0
        }
    
    def _save_cache_index(self):
        """Save the cache index file."""
        index_file = self.cache_dir / "index.json"
        with open(index_file, 'w') as f:
            json.dump(self.cache_index, f, indent=2)
    
    def cache_export(self, export_id: str, findings: List[Dict]) -> str:
        """
        Cache a processed SonarQube export.
        
        Args:
            export_id: Unique identifier for this export
            findings: List of processed findings
            
        Returns:
            Path to cached file
        """
        cache_file = self.cache_dir / f"{export_id}_findings.json"
        with open(cache_file, 'w') as f:
            json.dump(findings, f, indent=2)
        
        self.cache_index["cached_exports"][export_id] = {
            "timestamp": datetime.now().isoformat(),
            "finding_count": len(findings),
            "cache_file": str(cache_file)
        }
        self.cache_index["last_processed"] = datetime.now().isoformat()
        self.cache_index["total_ingestions"] += 1
        self._save_cache_index()
        
        return str(cache_file)
    
    def get_cached_findings(self, export_id: str) -> Optional[List[Dict]]:
        """Retrieve cached findings."""
        if export_id not in self.cache_index["cached_exports"]:
            return None
        cache_file = self.cache_index["cached_exports"][export_id]["cache_file"]
        if Path(cache_file).exists():
            with open(cache_file, 'r') as f:
                return json.load(f)
        return None
    
    def get_latest_findings(self) -> Optional[List[Dict]]:
        """Get the most recently cached findings."""
        if not self.cache_index["cached_exports"]:
            return None
        latest_id = max(
            self.cache_index["cached_exports"].items(),
            key=lambda x: x[1]["timestamp"]
        )[0]
        return self.get_cached_findings(latest_id)


class SonarQubeExportParser:
    """Parses SonarQube JSON and YAML exports."""
    
    def __init__(self):
        self.supported_formats = [".json", ".yaml", ".yml"]
    
    def parse_export(self, file_path: str) -> Optional[Dict]:
        """
        Parse a SonarQube export file.
        
        Args:
            file_path: Path to export file
            
        Returns:
            Parsed data dict or None
        """
        file_path = Path(file_path)
        if file_path.suffix.lower() not in self.supported_formats:
            raise ValueError(f"Unsupported format: {file_path.suffix}")
        
        try:
            if file_path.suffix.lower() == ".json":
                with open(file_path, 'r') as f:
                    return json.load(f)
            else:
                with open(file_path, 'r') as f:
                    return yaml.safe_load(f)
        except Exception as e:
            raise RuntimeError(f"Failed to parse {file_path}: {str(e)}")
    
    def extract_issues(self, export_data: Dict) -> List[Dict]:
        """
        Extract standardized issue format from SonarQube export.
        
        SonarQube export typically contains:
          {
            "issues": [
              {
                "key": "AVxxx",
                "component": "project:file.java",
                "rule": "java:S2077",
                "severity": "BLOCKER|CRITICAL|MAJOR|MINOR|INFO",
                "type": "VULNERABILITY|BUG|SECURITY_HOTSPOT|CODE_SMELL",
                "message": "...",
                "textRange": {...},
                "effort": "5min",
                "tags": ["security", "cwe"],
                "debt": "10min"
              }
            ]
          }
        
        Args:
            export_data: Parsed SonarQube export data
            
        Returns:
            List of standardized issue dicts
        """
        issues = []
        
        if "issues" not in export_data:
            return issues
        
        for issue in export_data.get("issues", []):
            standardized = {
                "key": issue.get("key", ""),
                "component": issue.get("component", ""),
                "rule": issue.get("rule", ""),
                "severity": self._normalize_severity(issue.get("severity", "INFO")),
                "type": issue.get("type", "CODE_SMELL"),
                "message": issue.get("message", ""),
                "status": issue.get("status", "OPEN"),
                "resolution": issue.get("resolution", None),
                "line": issue.get("line", None),
                "tags": issue.get("tags", []),
                "effort": issue.get("effort", "0min"),
                "debt": issue.get("debt", "0min"),
                "hash": issue.get("hash", self._compute_issue_hash(issue))
            }
            issues.append(standardized)
        
        return issues
    
    def _normalize_severity(self, severity_str: str) -> str:
        """Map SonarQube severity to standard levels."""
        mapping = {
            "BLOCKER": "Critical",
            "CRITICAL": "Critical",
            "MAJOR": "High",
            "MINOR": "Medium",
            "INFO": "Low"
        }
        return mapping.get(severity_str, "Medium")
    
    def _compute_issue_hash(self, issue: Dict) -> str:
        """Compute a stable hash for an issue (for tracking)."""
        content = f"{issue.get('component', '')}{issue.get('rule', '')}{issue.get('message', '')}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


class SonarQubeFindingsDiffer:
    """Compares old and new findings to identify changes."""
    
    def diff_findings(self, previous: List[Dict], current: List[Dict]) -> Dict:
        """
        Diff previous and current findings.
        
        Returns:
          {
            "new": [...],           # Issues in current but not previous
            "resolved": [...],      # Issues in previous but not current
            "changed_severity": [...],  # Issues where severity changed
            "unchanged": [...]      # Issues present in both
          }
        
        Args:
            previous: Previous findings list
            current: Current findings list
            
        Returns:
            Dict with categorized findings
        """
        if not previous:
            return {
                "new": current,
                "resolved": [],
                "changed_severity": [],
                "unchanged": []
            }
        
        previous_keys = {iss.get("key"): iss for iss in previous}
        current_keys = {iss.get("key"): iss for iss in current}
        
        new = []
        resolved = []
        changed_severity = []
        unchanged = []
        
        # Find resolved and unchanged
        for key, prev_issue in previous_keys.items():
            if key not in current_keys:
                resolved.append(prev_issue)
            else:
                curr_issue = current_keys[key]
                if prev_issue.get("severity") != curr_issue.get("severity"):
                    changed_severity.append({
                        "issue": curr_issue,
                        "old_severity": prev_issue.get("severity"),
                        "new_severity": curr_issue.get("severity")
                    })
                else:
                    unchanged.append(curr_issue)
        
        # Find new
        for key, curr_issue in current_keys.items():
            if key not in previous_keys:
                new.append(curr_issue)
        
        return {
            "new": new,
            "resolved": resolved,
            "changed_severity": changed_severity,
            "unchanged": unchanged
        }
    
    def generate_diff_report(self, diff_result: Dict) -> str:
        """Generate a human-readable diff report."""
        report = []
        report.append("=" * 70)
        report.append("SONARQUBE FINDINGS DIFF REPORT")
        report.append("=" * 70)
        
        report.append(f"\n📊 SUMMARY:")
        report.append(f"  New Issues:          {len(diff_result['new'])}")
        report.append(f"  Resolved Issues:     {len(diff_result['resolved'])}")
        report.append(f"  Severity Changes:    {len(diff_result['changed_severity'])}")
        report.append(f"  Unchanged Issues:    {len(diff_result['unchanged'])}")
        
        # New issues
        if diff_result['new']:
            report.append(f"\n🆕 NEW ISSUES ({len(diff_result['new'])}):")
            for issue in diff_result['new'][:10]:  # Show first 10
                report.append(f"  [{issue['severity']}] {issue['rule']}: {issue['message'][:60]}")
            if len(diff_result['new']) > 10:
                report.append(f"  ... and {len(diff_result['new']) - 10} more")
        
        # Resolved issues
        if diff_result['resolved']:
            report.append(f"\n✅ RESOLVED ISSUES ({len(diff_result['resolved'])}):")
            for issue in diff_result['resolved'][:10]:
                report.append(f"  [{issue['severity']}] {issue['rule']}: {issue['message'][:60]}")
            if len(diff_result['resolved']) > 10:
                report.append(f"  ... and {len(diff_result['resolved']) - 10} more")
        
        # Severity changes
        if diff_result['changed_severity']:
            report.append(f"\n⚠️  SEVERITY CHANGES ({len(diff_result['changed_severity'])}):")
            for change in diff_result['changed_severity'][:10]:
                issue = change['issue']
                old_sev = change['old_severity']
                new_sev = change['new_severity']
                report.append(f"  {issue['rule']}: {old_sev} → {new_sev}")
            if len(diff_result['changed_severity']) > 10:
                report.append(f"  ... and {len(diff_result['changed_severity']) - 10} more")
        
        report.append("\n" + "=" * 70)
        return "\n".join(report)


class SonarQubeIngestionEngine:
    """Main ingestion engine combining all components."""
    
    def __init__(self, cache_dir: str = "./cache", watch_dir: Optional[str] = None):
        """
        Initialize ingestion engine.
        
        Args:
            cache_dir: Directory for caching processed exports
            watch_dir: Optional directory to watch for exports
        """
        self.cache = SonarQubeIngestionCache(cache_dir)
        self.parser = SonarQubeExportParser()
        self.differ = SonarQubeFindingsDiffer()
        self.watch_dir = Path(watch_dir) if watch_dir else None
    
    def ingest_file(self, file_path: str) -> Dict:
        """
        Ingest a single SonarQube export file.
        
        Returns metadata about ingestion including diff results.
        """
        file_path = Path(file_path)
        
        # Parse the export
        export_data = self.parser.parse_export(str(file_path))
        current_findings = self.parser.extract_issues(export_data)
        
        # Get previous findings if any
        previous_findings = self.cache.get_latest_findings()
        
        # Compute diff
        diff_result = self.differ.diff_findings(
            previous_findings or [],
            current_findings
        )
        
        # Cache new findings
        export_id = f"{file_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        cache_path = self.cache.cache_export(export_id, current_findings)
        
        return {
            "success": True,
            "export_id": export_id,
            "file_path": str(file_path),
            "cache_path": cache_path,
            "total_findings": len(current_findings),
            "diff": {
                "new_count": len(diff_result['new']),
                "resolved_count": len(diff_result['resolved']),
                "severity_changes": len(diff_result['changed_severity']),
                "unchanged_count": len(diff_result['unchanged'])
            },
            "diff_report": self.differ.generate_diff_report(diff_result),
            "timestamp": datetime.now().isoformat()
        }
    
    def ingest_directory(self, directory: str) -> List[Dict]:
        """
        Ingest all SonarQube exports in a directory.
        
        Args:
            directory: Path to directory containing exports
            
        Returns:
            List of ingestion results
        """
        results = []
        dir_path = Path(directory)
        
        if not dir_path.exists():
            raise ValueError(f"Directory does not exist: {directory}")
        
        # Find all JSON/YAML files
        export_files = []
        for ext in self.parser.supported_formats:
            export_files.extend(dir_path.glob(f"*{ext}"))
        
        for file_path in export_files:
            try:
                result = self.ingest_file(str(file_path))
                results.append(result)
            except Exception as e:
                results.append({
                    "success": False,
                    "file_path": str(file_path),
                    "error": str(e)
                })
        
        return results
    
    def get_inventory(self) -> Dict:
        """Get the current ingestion inventory."""
        return {
            "total_ingestions": self.cache.cache_index["total_ingestions"],
            "last_processed": self.cache.cache_index["last_processed"],
            "cached_exports": list(self.cache.cache_index["cached_exports"].keys()),
            "cache_size_mb": sum(
                Path(v["cache_file"]).stat().st_size / (1024*1024)
                for v in self.cache.cache_index["cached_exports"].values()
                if Path(v["cache_file"]).exists()
            )
        }


if __name__ == "__main__":
    # Example usage
    engine = SonarQubeIngestionEngine(cache_dir="./sonar_cache")
    
    # Example: ingest a single file
    # result = engine.ingest_file("sonarqube_export.json")
    # print(json.dumps(result, indent=2))
    
    print("SonarQube Ingestion Engine initialized")
    print("Inventory:", json.dumps(engine.get_inventory(), indent=2))
