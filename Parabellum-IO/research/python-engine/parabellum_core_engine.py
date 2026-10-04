"""
parabellum_core_engine.py
=========================
Main orchestration engine for Parabellum IO - integrates SonarQube ingestion,
risk analysis, and compliance reporting into a unified workflow.

The core engine:
  1. Ingests SonarQube exports (JSON/YAML)
  2. Parses and diffs findings against cached state
  3. Enriches findings with CWE/NIST/risk analysis
  4. Generates compliance reports
  5. Stores audit trail
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Import subcomponents
from sonarqube_ingestion_engine import SonarQubeIngestionEngine
from risk_module import VulnerabilityAnalyzer
from compliance_reporter import ComplianceReporter
from cwe_database import SONARQUBE_RULE_TO_CWE


class ParabellumCoreEngine:
    """
    Main orchestration engine for vulnerability assessment and compliance reporting.
    """
    
    def __init__(self, 
                 workspace_dir: str = "./workspace",
                 cache_dir: str = "./cache",
                 reports_dir: str = "./reports"):
        """
        Initialize the Parabellum Core Engine.
        
        Args:
            workspace_dir: Root workspace directory
            cache_dir: Directory for caching processed data
            reports_dir: Directory for generated reports
        """
        self.workspace_dir = Path(workspace_dir)
        self.cache_dir = Path(cache_dir)
        self.reports_dir = Path(reports_dir)
        
        # Create directories
        for dir_path in [self.workspace_dir, self.cache_dir, self.reports_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize subcomponents
        self.sonar_engine = SonarQubeIngestionEngine(
            cache_dir=str(self.cache_dir / "sonarqube")
        )
        self.vulnerability_analyzer = VulnerabilityAnalyzer()
        self.compliance_reporter = ComplianceReporter(
            output_dir=str(self.reports_dir)
        )
        
        # Session tracking
        self.session_id = None
        self.session_log = []
    
    def start_session(self, project_name: str, description: str = "") -> str:
        """
        Start a new processing session.
        
        Args:
            project_name: Name of project being analyzed
            description: Optional session description
            
        Returns:
            Session ID
        """
        self.session_id = f"session_{project_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.session_log = [{
            "timestamp": datetime.now().isoformat(),
            "event": "SESSION_START",
            "project": project_name,
            "description": description
        }]
        
        self._log_event("Session started", {"project": project_name})
        return self.session_id
    
    def process_sonarqube_export(self, file_path: str) -> Dict:
        """
        Process a SonarQube export file through the full pipeline.
        
        Pipeline:
          1. Ingest & parse SonarQube export
          2. Diff against previous state
          3. Analyze each finding with risk scoring
          4. Generate compliance report
          5. Log results
        
        Args:
            file_path: Path to SonarQube export file (JSON or YAML)
            
        Returns:
            Complete analysis result
        """
        self._log_event("Processing SonarQube export", {"file": file_path})
        
        try:
            # Step 1: Ingest & parse
            ingest_result = self.sonar_engine.ingest_file(file_path)
            if not ingest_result.get("success"):
                raise Exception(f"Ingestion failed: {ingest_result.get('error')}")
            
            self._log_event("SonarQube export ingested successfully", ingest_result)
            
            # Get the parsed findings
            current_findings = self.sonar_engine.cache.get_cached_findings(
                ingest_result["export_id"]
            )
            
            # Step 2: Analyze findings
            analysis_result = self.vulnerability_analyzer.analyze_findings_batch(
                current_findings
            )
            
            self._log_event("Vulnerability analysis completed", {
                "total_findings": analysis_result["total_findings"],
                "critical": analysis_result["aggregate_metrics"].get("critical_count", 0)
            })
            
            # Step 3: Generate compliance report
            project_name = Path(file_path).stem
            report_path = self.compliance_reporter.generate_report(
                analysis_result,
                project_name
            )
            
            self._log_event("Compliance report generated", {"file": report_path})
            
            # Generate JSON summary
            summary_json = self.compliance_reporter.generate_summary_json(
                analysis_result,
                project_name
            )
            summary_path = str(self.reports_dir / f"{project_name}_summary.json")
            with open(summary_path, 'w') as f:
                f.write(summary_json)
            
            # Build complete result
            result = {
                "session_id": self.session_id,
                "project_name": project_name,
                "processing_timestamp": datetime.now().isoformat(),
                "status": "SUCCESS",
                "ingestion": {
                    "export_id": ingest_result["export_id"],
                    "total_findings": ingest_result["total_findings"],
                    "diff": ingest_result["diff"],
                    "diff_report": ingest_result.get("diff_report", "")
                },
                "analysis": {
                    "total_findings": analysis_result["total_findings"],
                    "aggregate_metrics": analysis_result["aggregate_metrics"],
                    "risk_assessment": analysis_result["overall_risk_assessment"]
                },
                "reporting": {
                    "compliance_report": report_path,
                    "summary_json": summary_path
                },
                "recommendations": {
                    "action_items": len(analysis_result["overall_risk_assessment"].get("requires_immediate_action", False)) > 0,
                    "policy_status": analysis_result["overall_risk_assessment"].get("policy_compliance", "UNKNOWN")
                }
            }
            
            self._log_event("SonarQube export processing completed", {"status": "SUCCESS"})
            return result
            
        except Exception as e:
            error_result = {
                "session_id": self.session_id,
                "status": "FAILED",
                "error": str(e),
                "file_path": file_path,
                "timestamp": datetime.now().isoformat()
            }
            self._log_event("SonarQube processing failed", {"error": str(e)})
            return error_result
    
    def process_directory(self, directory: str) -> Dict:
        """
        Process all SonarQube exports in a directory.
        
        Args:
            directory: Directory containing SonarQube exports
            
        Returns:
            Summary of all processed files
        """
        self._log_event("Processing directory", {"directory": directory})
        
        results = []
        errors = []
        
        dir_path = Path(directory)
        if not dir_path.exists():
            return {
                "status": "FAILED",
                "error": f"Directory does not exist: {directory}"
            }
        
        # Find all SonarQube exports
        for ext in [".json", ".yaml", ".yml"]:
            for file_path in dir_path.glob(f"*{ext}"):
                result = self.process_sonarqube_export(str(file_path))
                if result.get("status") == "SUCCESS":
                    results.append(result)
                else:
                    errors.append(result)
        
        return {
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(),
            "directory": directory,
            "total_files_processed": len(results) + len(errors),
            "successful": len(results),
            "failed": len(errors),
            "results": results,
            "errors": errors if errors else None
        }
    
    def generate_portfolio_report(self, project_analyses: List[Dict]) -> str:
        """
        Generate a portfolio-level compliance report combining multiple projects.
        
        Args:
            project_analyses: List of analysis results from multiple projects
            
        Returns:
            Path to portfolio report
        """
        self._log_event("Generating portfolio report", {
            "projects": len(project_analyses)
        })
        
        # Aggregate data
        portfolio_data = {
            "total_projects": len(project_analyses),
            "total_findings": sum(p.get("analysis", {}).get("total_findings", 0) for p in project_analyses),
            "total_critical": sum(p.get("analysis", {}).get("aggregate_metrics", {}).get("critical_count", 0) for p in project_analyses),
            "projects": []
        }
        
        # Extract project info
        for analysis in project_analyses:
            portfolio_data["projects"].append({
                "project_name": analysis.get("project_name"),
                "total_findings": analysis.get("analysis", {}).get("total_findings", 0),
                "critical_count": analysis.get("analysis", {}).get("aggregate_metrics", {}).get("critical_count", 0),
                "risk_level": analysis.get("analysis", {}).get("risk_assessment", {}).get("portfolio_risk_level", "Unknown"),
                "policy_status": analysis.get("analysis", {}).get("risk_assessment", {}).get("policy_compliance", "UNKNOWN")
            })
        
        # Save portfolio report
        report_name = f"portfolio_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = str(self.reports_dir / report_name)
        
        with open(report_path, 'w') as f:
            json.dump(portfolio_data, f, indent=2)
        
        self._log_event("Portfolio report generated", {"file": report_path})
        return report_path
    
    def get_session_summary(self) -> Dict:
        """Get session summary and logs."""
        return {
            "session_id": self.session_id,
            "start_time": self.session_log[0].get("timestamp") if self.session_log else None,
            "end_time": datetime.now().isoformat(),
            "total_events": len(self.session_log),
            "events": self.session_log
        }
    
    def save_session_log(self) -> str:
        """Save session log to file."""
        log_name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        log_path = str(self.cache_dir / log_name)
        
        with open(log_path, 'w') as f:
            json.dump(self.get_session_summary(), f, indent=2)
        
        return log_path
    
    def _log_event(self, event_name: str, details: Optional[Dict] = None):
        """Log an event in the session."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event_name,
            "details": details or {}
        }
        self.session_log.append(log_entry)
    
    def get_engine_status(self) -> Dict:
        """Get current engine status and statistics."""
        return {
            "session_id": self.session_id,
            "workspace_dir": str(self.workspace_dir),
            "cache_dir": str(self.cache_dir),
            "reports_dir": str(self.reports_dir),
            "sonarqube_cache": self.sonar_engine.get_inventory(),
            "session_events": len(self.session_log),
            "timestamp": datetime.now().isoformat()
        }


# ──────────────────────────────────────────────────────────────────
# Example Usage & Main Script
# ──────────────────────────────────────────────────────────────────

def example_workflow():
    """Example of a complete workflow."""
    
    print("Initializing Parabellum Core Engine...")
    engine = ParabellumCoreEngine(
        workspace_dir="./parabellum_workspace",
        cache_dir="./parabellum_cache",
        reports_dir="./parabellum_reports"
    )
    
    print("Starting session...")
    session_id = engine.start_session(
        project_name="TestProject",
        description="Initial security scan"
    )
    print(f"Session ID: {session_id}")
    
    print("\nEngine Status:")
    print(json.dumps(engine.get_engine_status(), indent=2))
    
    # Process would continue with actual SonarQube exports...
    
    print("\nSession Summary:")
    print(json.dumps(engine.get_session_summary(), indent=2))
    
    # Save session
    log_path = engine.save_session_log()
    print(f"\nSession log saved: {log_path}")


if __name__ == "__main__":
    example_workflow()
