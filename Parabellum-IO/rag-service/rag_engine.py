"""
Multi-Framework RAG Engine — ChromaDB + Sentence Transformers
Supports: NIST CSF 2.0, ISO 27001, ISO 27034, NIST SP 800-53, CIS Controls v8, OWASP ASVS v4
Each framework gets its own ChromaDB collection for isolated, accurate retrieval.
"""

import os
import chromadb
from sentence_transformers import SentenceTransformer

# Framework data imports
from nist_csf_data  import NIST_CSF_2_CONTROLS
from iso27001_data  import ISO27001_CONTROLS
from iso27034_data  import ISO27034_CONTROLS
from nist_sp800_data import NIST_SP800_CONTROLS
from cis_controls_data import CIS_CONTROLS
from owasp_asvs_data import OWASP_ASVS_CONTROLS

# ── Configuration ─────────────────────────────────────────────────
MODEL_NAME   = "all-MiniLM-L6-v2"
CHROMA_DIR   = os.path.join(os.path.dirname(__file__), "chroma_db")
TOP_K        = 5

# ── Framework Registry ─────────────────────────────────────────────
# Each entry: slug → { controls, id_field, group_field, collection_name }
FRAMEWORKS = {
    "nist_csf": {
        "label":       "NIST CSF 2.0",
        "controls":    NIST_CSF_2_CONTROLS,
        "id_field":    "id",
        "group_field": "function",
        "collection":  "nist_csf_controls",
    },
    "iso27001": {
        "label":       "ISO 27001:2022",
        "controls":    ISO27001_CONTROLS,
        "id_field":    "id",
        "group_field": "domain",
        "collection":  "iso27001_controls",
    },
    "iso27034": {
        "label":       "ISO 27034",
        "controls":    ISO27034_CONTROLS,
        "id_field":    "id",
        "group_field": "domain",
        "collection":  "iso27034_controls",
    },
    "nist_sp800": {
        "label":       "NIST SP 800-53 Rev 5",
        "controls":    NIST_SP800_CONTROLS,
        "id_field":    "id",
        "group_field": "family",
        "collection":  "nist_sp800_controls",
    },
    "cis_controls": {
        "label":       "CIS Controls v8",
        "controls":    CIS_CONTROLS,
        "id_field":    "id",
        "group_field": "ig_level",
        "collection":  "cis_controls",
    },
    "owasp_asvs": {
        "label":       "OWASP ASVS v4",
        "controls":    OWASP_ASVS_CONTROLS,
        "id_field":    "id",
        "group_field": "chapter",
        "collection":  "owasp_asvs_controls",
    },
}

# ── Singleton state ────────────────────────────────────────────────
_model: SentenceTransformer = None
_chroma_client: chromadb.PersistentClient = None
_collections: dict = {}   # slug → chromadb collection


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        print(f"[RAG] Loading embedding model: {MODEL_NAME}")
        _model = SentenceTransformer(MODEL_NAME)
        print("[RAG] Model loaded.")
    return _model


def _get_chroma_client() -> chromadb.PersistentClient:
    global _chroma_client
    if _chroma_client is None:
        _chroma_client = chromadb.PersistentClient(path=CHROMA_DIR)
    return _chroma_client


def _get_collection(slug: str):
    global _collections
    if slug not in _collections:
        client = _get_chroma_client()
        col_name = FRAMEWORKS[slug]["collection"]
        _collections[slug] = client.get_or_create_collection(
            name=col_name,
            metadata={"hnsw:space": "cosine"},
        )
    return _collections[slug]


def _build_document_text(control: dict, fw_meta: dict) -> str:
    """Build a rich text representation of any framework control for embedding."""
    id_field    = fw_meta["id_field"]
    group_field = fw_meta["group_field"]
    keywords    = " ".join(control.get("sonarqube_keywords", []))
    cwe         = " ".join(control.get("cwe_refs", []))
    return (
        f"{control.get(id_field, '')} "
        f"{control.get(group_field, '')} "
        f"{control.get('title', '')} "
        f"{control.get('description', '')} "
        f"keywords: {keywords} "
        f"cwe: {cwe}"
    ).strip()


# ── Public API ─────────────────────────────────────────────────────

def build_index(slug: str, extra_documents: list[dict] | None = None) -> int:
    """
    Build (or rebuild) the ChromaDB index for a specific framework.
    extra_documents: optional feedback docs with keys { id, text, metadata }
    """
    if slug not in FRAMEWORKS:
        raise ValueError(f"Unknown framework slug: {slug}")

    fw_meta   = FRAMEWORKS[slug]
    controls  = fw_meta["controls"]
    client    = _get_chroma_client()
    col_name  = fw_meta["collection"]
    model     = _get_model()

    # Delete and recreate the collection cleanly
    try:
        client.delete_collection(col_name)
    except Exception:
        pass

    global _collections
    _collections[slug] = client.get_or_create_collection(
        name=col_name,
        metadata={"hnsw:space": "cosine"},
    )
    collection = _collections[slug]

    ids, documents, metadatas = [], [], []
    id_field    = fw_meta["id_field"]
    group_field = fw_meta["group_field"]

    for ctrl in controls:
        doc_text = _build_document_text(ctrl, fw_meta)
        ctrl_id  = ctrl[id_field]
        ids.append(ctrl_id)
        documents.append(doc_text)
        metadatas.append({
            "id":          ctrl_id,
            "group":       ctrl.get(group_field, ""),
            "title":       ctrl.get("title", ""),
            "framework":   slug,
            "source":      f"{slug}_base",
        })

    # Feedback documents
    if extra_documents:
        for doc in extra_documents:
            fb_id = f"fb_{doc['id']}"
            ids.append(fb_id)
            documents.append(doc["text"])
            metadatas.append({**doc.get("metadata", {}), "source": "feedback"})

    embeddings = model.encode(documents, show_progress_bar=True).tolist()
    collection.add(ids=ids, documents=documents, metadatas=metadatas, embeddings=embeddings)

    total = len(ids)
    print(f"[RAG:{slug}] Indexed {total} documents ({len(controls)} base + {total - len(controls)} feedback)")
    return total


def build_all_indexes(extra_documents: dict[str, list] | None = None) -> dict[str, int]:
    """Build (or rebuild) indexes for ALL registered frameworks."""
    results = {}
    for slug in FRAMEWORKS:
        extras = (extra_documents or {}).get(slug)
        results[slug] = build_index(slug, extra_documents=extras)
    return results


def map_finding(finding_text: str, slug: str = "nist_csf", top_k: int = TOP_K) -> list[dict]:
    """
    Map a SonarQube finding to the top-K most relevant controls in the given framework.

    Returns a list of dicts:
    [
      {
        "control_id": "PR.DS-01",
        "group":       "PROTECT",          # function / domain / family / ig_level / chapter
        "title":       "...",
        "framework":   "nist_csf",
        "framework_label": "NIST CSF 2.0",
        "confidence":  0.87,
      }, ...
    ]
    """
    if slug not in FRAMEWORKS:
        raise ValueError(f"Unknown framework: {slug}")

    collection = _get_collection(slug)
    model      = _get_model()

    if collection.count() == 0:
        raise RuntimeError(f"Index for '{slug}' is empty. Call build_index('{slug}') first.")

    embedding = model.encode([finding_text])[0].tolist()
    results   = collection.query(
        query_embeddings=[embedding],
        n_results=min(top_k, collection.count()),
        include=["metadatas", "distances"],
    )

    controls = []
    for meta, distance in zip(results["metadatas"][0], results["distances"][0]):
        confidence = round(float(1 - distance), 4)
        controls.append({
            "control_id":      meta.get("id", ""),
            "group":           meta.get("group", ""),
            "title":           meta.get("title", ""),
            "framework":       slug,
            "framework_label": FRAMEWORKS[slug]["label"],
            "confidence":      max(0.0, confidence),
            "source":          meta.get("source", f"{slug}_base"),
        })

    # Deduplicate by control_id (keep highest confidence)
    seen = {}
    for ctrl in controls:
        cid = ctrl["control_id"]
        if cid not in seen or ctrl["confidence"] > seen[cid]["confidence"]:
            seen[cid] = ctrl

    return sorted(seen.values(), key=lambda x: x["confidence"], reverse=True)[:top_k]


def map_finding_all_frameworks(finding_text: str, top_k: int = 3) -> dict[str, list[dict]]:
    """Map a single finding to all registered frameworks simultaneously."""
    return {slug: map_finding(finding_text, slug=slug, top_k=top_k) for slug in FRAMEWORKS}


def get_index_stats() -> dict:
    """Return per-framework and total document counts."""
    stats = {"total": 0, "frameworks": {}}
    for slug in FRAMEWORKS:
        try:
            col   = _get_collection(slug)
            count = col.count()
            stats["frameworks"][slug] = {
                "label":     FRAMEWORKS[slug]["label"],
                "documents": count,
            }
            stats["total"] += count
        except Exception:
            stats["frameworks"][slug] = {"label": FRAMEWORKS[slug]["label"], "documents": 0}
    # Backward-compat key
    stats["indexed_documents"] = stats["total"]
    return stats


def get_framework_controls(slug: str) -> list[dict]:
    """Return all controls for a given framework slug."""
    if slug not in FRAMEWORKS:
        raise ValueError(f"Unknown framework: {slug}")
    fw_meta  = FRAMEWORKS[slug]
    controls = fw_meta["controls"]
    id_field    = fw_meta["id_field"]
    group_field = fw_meta["group_field"]
    return [
        {
            "id":        c[id_field],
            "group":     c.get(group_field, ""),
            "title":     c.get("title", ""),
            "framework": slug,
        }
        for c in controls
    ]
