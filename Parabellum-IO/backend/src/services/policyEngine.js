import fs from 'fs';
import path from 'path';

// ── Built-in Policy Library ───────────────────────────────────────────────
export const POLICY_LIBRARY = [
  // Container Security
  {
    id: "POL-C01",
    name: "Avoid running as root",
    category: "Container Security",
    severity: "Critical",
    description: "Dockerfiles should not run as root. A USER instruction must be specified.",
    nistControls: ["PR.AA-05", "PR.PS-01"],
    target: "Dockerfile",
    check: (content) => {
      if (!content.includes('USER ')) return "Missing USER instruction. Container runs as root by default.";
      if (content.match(/USER\s+root/i)) return "Explicitly running as root user.";
      return null;
    }
  },
  {
    id: "POL-C02",
    name: "Avoid 'latest' tag",
    category: "Container Security",
    severity: "High",
    description: "Docker base images should be pinned to a specific version, not 'latest'.",
    nistControls: ["ID.RA-01", "PR.PS-01"],
    target: "Dockerfile",
    check: (content) => {
      if (content.match(/FROM\s+[^:]+(?::latest|\s*$)/mi)) return "Base image uses 'latest' or unspecified version tag.";
      return null;
    }
  },
  {
    id: "POL-C03",
    name: "Missing HEALTHCHECK",
    category: "Container Security",
    severity: "Medium",
    description: "Docker containers should define a HEALTHCHECK to ensure availability.",
    nistControls: ["DE.CM-01"],
    target: "Dockerfile",
    check: (content) => {
      if (!content.includes('HEALTHCHECK')) return "No HEALTHCHECK instruction defined.";
      return null;
    }
  },

  // Dependencies
  {
    id: "POL-D01",
    name: "Avoid wildcard versions",
    category: "Dependencies",
    severity: "Medium",
    description: "Package versions should be pinned. Avoid using '*' for dependency versions.",
    nistControls: ["PR.PS-01"],
    target: "package.json",
    check: (content) => {
      try {
        const pkg = JSON.parse(content);
        const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
        const wildcards = Object.entries(deps).filter(([_, v]) => v === '*').map(([k]) => k);
        if (wildcards.length > 0) return `Wildcard versions found for: ${wildcards.join(', ')}`;
      } catch (e) { /* ignore parse errors */ }
      return null;
    }
  },

  // Secrets & Environment
  {
    id: "POL-S01",
    name: "Hardcoded Passwords",
    category: "Secrets & Environment",
    severity: "Critical",
    description: "Environment files must not contain hardcoded sensitive passwords.",
    nistControls: ["PR.DS-01", "PR.AA-01"],
    target: ".env",
    check: (content) => {
      const lines = content.split('\n');
      const passwordRegex = /password\s*=\s*(?!<.*>|YOUR_.*)[\w@#$!%^&*]+/i;
      const matches = lines.filter(l => passwordRegex.test(l) && !l.trim().startsWith('#'));
      if (matches.length > 0) return "Potential hardcoded password found in environment variables.";
      return null;
    }
  },
  {
    id: "POL-S02",
    name: "Exposed API Keys",
    category: "Secrets & Environment",
    severity: "Critical",
    description: "Environment files should not contain real API keys in the repository.",
    nistControls: ["PR.DS-01"],
    target: ".env",
    check: (content) => {
      if (content.match(/API_KEY\s*=\s*[A-Za-z0-9_-]{15,}/i)) return "Potential hardcoded API key found.";
      if (content.match(/SECRET\s*=\s*[A-Za-z0-9_-]{15,}/i)) return "Potential hardcoded secret found.";
      return null;
    }
  },

  // CI/CD Security
  {
    id: "POL-CI01",
    name: "Missing Security Scanning Step",
    category: "CI/CD Pipeline",
    severity: "High",
    description: "CI/CD workflows should include security scanning steps (SAST/SCA).",
    nistControls: ["ID.RA-01", "PR.PS-06"],
    target: ".github/workflows",
    check: (content) => {
      const lower = content.toLowerCase();
      const hasScan = lower.includes('sonar') || lower.includes('snyk') || lower.includes('trivy') || lower.includes('security');
      if (!hasScan) return "No security scanning tools detected in the CI/CD pipeline workflow.";
      return null;
    }
  }
];

// ── File Discovery ────────────────────────────────────────────────────────
function findTargetFiles(dirPath, targetType) {
  let results = [];
  try {
    const list = fs.readdirSync(dirPath);
    for (const file of list) {
      if (file === 'node_modules' || file === '.git') continue;
      const fullPath = path.join(dirPath, file);
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory()) {
        if (targetType === '.github/workflows' && file === '.github') {
          const wfPath = path.join(fullPath, 'workflows');
          if (fs.existsSync(wfPath)) {
            const ymls = fs.readdirSync(wfPath).filter(f => f.endsWith('.yml') || f.endsWith('.yaml'));
            results.push(...ymls.map(y => path.join(wfPath, y)));
          }
        } else {
          results = results.concat(findTargetFiles(fullPath, targetType));
        }
      } else {
        if (targetType === 'Dockerfile' && file.includes('Dockerfile')) results.push(fullPath);
        if (targetType === 'package.json' && file === 'package.json') results.push(fullPath);
        if (targetType === '.env' && (file === '.env' || file === '.env.example')) results.push(fullPath);
      }
    }
  } catch (err) {
    console.warn(`Error reading dir ${dirPath}:`, err.message);
  }
  return results;
}

// ── Scan Engine ───────────────────────────────────────────────────────────
/**
 * Scans a given project directory against all policies.
 * @param {string} projectPath - Absolute path to the project to scan.
 * @returns {Object} { violations: [], summary: {} }
 */
export function scanProject(projectPath) {
  const violations = [];
  const filesScanned = new Set();
  
  if (!fs.existsSync(projectPath)) {
    return { violations, summary: { error: 'Project directory not found.' } };
  }

  for (const policy of POLICY_LIBRARY) {
    const targetFiles = findTargetFiles(projectPath, policy.target);
    
    for (const file of targetFiles) {
      filesScanned.add(file);
      try {
        const content = fs.readFileSync(file, 'utf-8');
        const violationMsg = policy.check(content);
        
        if (violationMsg) {
          violations.push({
            policyId: policy.id,
            policyName: policy.name,
            category: policy.category,
            severity: policy.severity,
            nistControls: policy.nistControls,
            file: path.relative(projectPath, file),
            message: violationMsg
          });
        }
      } catch (e) {
        console.warn(`Could not read file ${file}:`, e.message);
      }
    }
  }

  // Calculate Policy Score
  let score = 100;
  for (const v of violations) {
    if (v.severity === 'Critical') score -= 15;
    else if (v.severity === 'High') score -= 8;
    else if (v.severity === 'Medium') score -= 3;
    else if (v.severity === 'Low') score -= 1;
  }
  score = Math.max(0, score);

  const summary = {
    totalFilesScanned: filesScanned.size,
    totalViolations: violations.length,
    critical: violations.filter(v => v.severity === 'Critical').length,
    high: violations.filter(v => v.severity === 'High').length,
    medium: violations.filter(v => v.severity === 'Medium').length,
    low: violations.filter(v => v.severity === 'Low').length,
    policyScore: score
  };

  return { violations, summary };
}
