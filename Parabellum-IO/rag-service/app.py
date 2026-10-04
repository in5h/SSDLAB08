"""
Parabellum IO — Multi-Framework GRC RAG Microservice
FastAPI server that maps SonarQube findings to security framework controls
and learns from human feedback over time.

Supported frameworks:
  nist_csf    — NIST CSF 2.0 (106 controls)
  iso27001    — ISO 27001:2022 Annex A
  iso27034    — ISO 27034 Application Security
  nist_sp800  — NIST SP 800-53 Rev 5
  cis_controls — CIS Controls v8
  owasp_asvs  — OWASP ASVS v4
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List

import feedback_store
import rag_engine
from nist_csf_data import CONTROLS_BY_ID, NIST_CSF_2_CONTROLS


# ── Startup/Shutdown ───────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[RAG Service] Starting up — building all framework indexes…")
    feedback_store.init_db()

    stats = rag_engine.get_index_stats()
    if stats["total"] == 0:
        print("[RAG Service] No index found — building from all 6 framework knowledge bases…")
        rag_engine.build_all_indexes()
    else:
        print(f"[RAG Service] Loaded existing index ({stats['total']} total documents across all frameworks)")

    yield
    print("[RAG Service] Shutting down.")


app = FastAPI(
    title="Parabellum IO — Multi-Framework GRC RAG Service",
    description="Maps SonarQube security findings to NIST CSF 2.0, ISO 27001, ISO 27034, NIST SP 800-53, CIS Controls v8, and OWASP ASVS v4",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ──────────────────────────────────────

class MapRequest(BaseModel):
    finding: str
    top_k: Optional[int] = 5

class MultiMapRequest(BaseModel):
    finding: str
    top_k: Optional[int] = 3
    frameworks: Optional[List[str]] = None   # None = all frameworks

class FeedbackRequest(BaseModel):
    finding_text: str
    control_id: str
    source: Optional[str] = "human"

class ScoreRequest(BaseModel):
    total_issues: int
    failed_controls: List[dict] = []


# ── Health & Stats ─────────────────────────────────────────────────

@app.get("/health")
def health():
    """Health check — returns per-framework document counts."""
    stats = rag_engine.get_index_stats()
    return {"status": "ok", **stats}


@app.get("/stats")
def get_stats():
    """Extended stats: index counts + feedback store totals."""
    return {
        "index":    rag_engine.get_index_stats(),
        "feedback": feedback_store.get_stats(),
    }


# ── Framework Discovery ────────────────────────────────────────────

@app.get("/frameworks")
def list_frameworks():
    """List all available frameworks with their control counts."""
    result = []
    for slug, meta in rag_engine.FRAMEWORKS.items():
        result.append({
            "slug":          slug,
            "label":         meta["label"],
            "control_count": len(meta["controls"]),
            "group_field":   meta["group_field"],
        })
    return {"frameworks": result, "total": len(result)}


@app.get("/frameworks/{framework}/controls")
def list_framework_controls(framework: str):
    """List all controls for a specific framework."""
    try:
        controls = rag_engine.get_framework_controls(framework)
        return {"framework": framework, "total": len(controls), "controls": controls}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ── Mapping Endpoints ──────────────────────────────────────────────

@app.post("/map")
def map_finding_nist(req: MapRequest):
    """
    [Backward-compatible] Map a finding to NIST CSF 2.0 controls.
    Also stores the top result as auto-feedback.
    """
    if not req.finding or not req.finding.strip():
        raise HTTPException(status_code=400, detail="finding must not be empty")
    try:
        controls = rag_engine.map_finding(req.finding.strip(), slug="nist_csf", top_k=req.top_k)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    # Auto-feedback for NIST CSF (existing behaviour)
    if controls:
        top = controls[0]
        ctrl_meta = CONTROLS_BY_ID.get(top["control_id"], {})
        feedback_store.store_feedback(
            finding_text=req.finding.strip(),
            control_id=top["control_id"],
            function=ctrl_meta.get("function", top.get("group", "")),
            category=ctrl_meta.get("category", ""),
            title=top["title"],
            confidence=top["confidence"],
            source="auto",
        )

    # Reshape output to match legacy format expected by compliance.js
    reshaped = []
    for c in controls:
        ctrl_meta = CONTROLS_BY_ID.get(c["control_id"], {})
        reshaped.append({
            "control_id": c["control_id"],
            "function":   ctrl_meta.get("function", c.get("group", "")),
            "category":   ctrl_meta.get("category", ""),
            "title":      c["title"],
            "confidence": c["confidence"],
            "source":     c["source"],
        })

    return {"finding": req.finding, "controls": reshaped}


@app.post("/map/multi")
def map_finding_multi(req: MultiMapRequest):
    """
    Map a finding to ALL (or selected) frameworks simultaneously.
    Returns a dict keyed by framework slug.
    """
    if not req.finding or not req.finding.strip():
        raise HTTPException(status_code=400, detail="finding must not be empty")

    slugs = req.frameworks or list(rag_engine.FRAMEWORKS.keys())
    results = {}
    for slug in slugs:
        if slug not in rag_engine.FRAMEWORKS:
            continue
        try:
            results[slug] = rag_engine.map_finding(req.finding.strip(), slug=slug, top_k=req.top_k)
        except RuntimeError:
            results[slug] = []

    return {"finding": req.finding, "mappings": results}


@app.post("/map/{framework}")
def map_finding_framework(framework: str, req: MapRequest):
    """
    Map a finding to controls of a specific framework.
    Valid framework slugs: nist_csf, iso27001, iso27034, nist_sp800, cis_controls, owasp_asvs
    """
    if not req.finding or not req.finding.strip():
        raise HTTPException(status_code=400, detail="finding must not be empty")
    try:
        controls = rag_engine.map_finding(req.finding.strip(), slug=framework, top_k=req.top_k)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    return {"finding": req.finding, "framework": framework, "controls": controls}


# ── Feedback ───────────────────────────────────────────────────────

@app.post("/feedback")
def submit_feedback(req: FeedbackRequest):
    """Store a human-confirmed NIST CSF mapping (backward-compatible)."""
    if req.control_id not in CONTROLS_BY_ID:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown control_id: {req.control_id}. Must be a valid NIST CSF 2.0 subcategory ID.",
        )
    ctrl   = CONTROLS_BY_ID[req.control_id]
    row_id = feedback_store.store_feedback(
        finding_text=req.finding_text,
        control_id=req.control_id,
        function=ctrl["function"],
        category=ctrl["category"],
        title=ctrl["title"],
        confidence=1.0,
        source=req.source or "human",
    )
    return {
        "status":  "stored",
        "id":      row_id,
        "message": f"Mapping '{req.finding_text[:60]}…' → {req.control_id} saved. Run /retrain to apply.",
    }


@app.post("/retrain")
def retrain():
    """Rebuild ALL framework ChromaDB indexes."""
    print("[RAG Service] Retraining all framework indexes…")
    feedback_docs = feedback_store.get_feedback_as_rag_documents()
    totals = rag_engine.build_all_indexes()
    total  = sum(totals.values())
    return {
        "status":             "ok",
        "documents_indexed":  total,
        "per_framework":      totals,
        "feedback_documents": len(feedback_docs),
        "message":            f"All indexes rebuilt ({total} total documents).",
    }


@app.post("/retrain/{framework}")
def retrain_framework(framework: str):
    """Rebuild the index for a single framework."""
    if framework not in rag_engine.FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")
    print(f"[RAG Service] Retraining index for {framework}…")
    total = rag_engine.build_index(framework)
    return {
        "status":            "ok",
        "framework":         framework,
        "documents_indexed": total,
    }


# ── Controls Lookup (NIST CSF — backward-compat) ─────────────────

@app.get("/controls")
def list_controls():
    """Return all NIST CSF 2.0 controls."""
    return {
        "total":    len(NIST_CSF_2_CONTROLS),
        "controls": [
            {"id": c["id"], "function": c["function"], "category": c["category"], "title": c["title"]}
            for c in NIST_CSF_2_CONTROLS
        ],
    }


@app.get("/controls/{control_id}")
def get_control(control_id: str):
    """Return full details for a single NIST CSF 2.0 control."""
    ctrl = CONTROLS_BY_ID.get(control_id.upper())
    if not ctrl:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    return ctrl


# ── Scoring ────────────────────────────────────────────────────────

SEV_WEIGHTS = {
    "BLOCKER":  20,
    "CRITICAL": 15,
    "MAJOR":    8,
    "HIGH":     8,
    "MINOR":    3,
    "MEDIUM":   3,
    "INFO":     1,
    "LOW":      1,
}

NIST_CSF_FUNCTIONS = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]


def _calculate_score_generic(req: ScoreRequest, group_field: str = "function", groups: Optional[List[str]] = None):
    """
    Shared penalty-based scoring logic used by all framework score endpoints.
    group_field: the field that groups controls (function / domain / family / ig_level / chapter)
    groups: list of known group values; if None, derived dynamically from failed_controls
    """
    overall_score = 100.0

    # Collect unique groups from the failed controls if not provided
    if groups is None:
        groups = list({ctrl.get(group_field, "General") for ctrl in req.failed_controls})
    if not groups:
        groups = ["General"]

    group_scores      = {g: 100.0 for g in groups}
    group_violations  = {g: 0     for g in groups}
    group_failed_ctrl = {g: []    for g in groups}

    for ctrl in req.failed_controls:
        grp        = ctrl.get(group_field, groups[0] if groups else "General")
        if grp not in group_scores:
            grp = groups[0] if groups else "General"

        violations = ctrl.get("violations", [])
        group_violations[grp]  += len(violations)
        group_failed_ctrl[grp].append(ctrl.get("control_id"))

        ctrl_penalty    = 0
        max_sev_penalty = 0
        for v in violations:
            sev = str(v.get("severity", "MINOR")).upper()
            w   = SEV_WEIGHTS.get(sev, 3)
            ctrl_penalty += w
            if w > max_sev_penalty:
                max_sev_penalty = w

        control_penalty   = max_sev_penalty + (ctrl_penalty * 0.2)
        overall_score    -= control_penalty
        group_scores[grp] -= control_penalty

    overall_score = max(0, min(100, round(overall_score)))

    breakdown = []
    for grp in groups:
        score  = max(0, min(100, round(group_scores[grp])))
        status = "PASS" if score >= 80 else "WARN" if score >= 60 else "FAIL"
        if group_violations[grp] > 0 and status == "PASS":
            status = "WARN"
        breakdown.append({
            group_field:     grp,
            "score":         score,
            "status":        status,
            "violations":    group_violations[grp],
            "failedControls": group_failed_ctrl[grp],
        })

    grade  = 'A' if overall_score >= 90 else 'B' if overall_score >= 75 else 'C' if overall_score >= 60 else 'D' if overall_score >= 40 else 'F'
    status = 'PASS' if overall_score >= 70 else 'FAIL'

    if req.total_issues == 0 and not req.failed_controls:
        overall_score = 100
        grade  = 'A'
        status = 'PASS'

    return {
        "overall":   {"score": overall_score, "grade": grade, "status": status},
        "breakdown": breakdown,
    }


@app.post("/score")
def calculate_score(req: ScoreRequest):
    """
    [Backward-compatible] Penalty-based compliance scoring for NIST CSF.
    Uses NIST CSF functions as the grouping dimension.
    """
    return _calculate_score_generic(req, group_field="function", groups=NIST_CSF_FUNCTIONS)


@app.post("/score/{framework}")
def calculate_score_framework(framework: str, req: ScoreRequest):
    """
    Penalty-based compliance scoring for any registered framework.
    The grouping dimension adapts to the framework (function / domain / family / ig_level / chapter).
    """
    if framework not in rag_engine.FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")

    fw_meta     = rag_engine.FRAMEWORKS[framework]
    group_field = fw_meta["group_field"]

    # Collect unique group values from the framework's controls
    groups = list({c.get(group_field, "General") for c in fw_meta["controls"]})

    result = _calculate_score_generic(req, group_field=group_field, groups=groups)
    result["framework"]       = framework
    result["framework_label"] = fw_meta["label"]
    return result


# ── Entry point ────────────────────────────────────────────────────
if __name__ == "__main__":
    import os
    import uvicorn
    # Must match RAG_SERVICE_URL in backend/.env (default http://localhost:5000)
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.environ.get("RAG_PORT", "5000")), reload=False)
