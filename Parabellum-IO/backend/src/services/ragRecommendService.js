/**
 * ragRecommendService.js — Retrieval-Augmented recommendations and framework mappings.
 *
 * Retrieval: for each finding we retrieve the most relevant controls from all six
 * frameworks (NIST CSF 2.0, ISO 27001, CIS v8, NIST SP 800-53, ISO 27034, OWASP ASVS).
 *   1. Python RAG service (sentence-transformers + ChromaDB) when it is running, or
 *   2. the built-in BM25 retriever over the same control texts (offline fallback).
 * Rule-based mappings (grcMappingService) are merged in so well-known rules always
 * map to the right controls.
 *
 * Generation: the retrieved control texts + the finding + its code evidence are given
 * to Gemini (when GEMINI_API_KEY is set) to write the recommendation; otherwise a
 * deterministic template turns the retrieved controls and fix plan into the advice.
 */
import { createRequire } from "node:module";
import { mapIssueToGRC } from "./grcMappingService.js";
import { askLLM, isGeminiConfigured } from "./geminiClient.js";
import { resolveThreatMapping } from "./threatMappings.js";

const require = createRequire(import.meta.url);
const CATALOG = require("../data/controlCatalog.json");
const RAG_BASE = () => process.env.RAG_SERVICE_URL || "http://localhost:5000";

export const FRAMEWORKS = {
  nist_csf:     { label: "NIST CSF 2.0",    grcKey: "nist_csf" },
  iso27001:     { label: "ISO 27001:2022",  grcKey: "iso_27001" },
  cis_controls: { label: "CIS Controls v8", grcKey: "cis_controls" },
  nist_sp800:   { label: "NIST SP 800-53",  grcKey: "nist_sp800" },
  owasp_asvs:   { label: "OWASP ASVS v4",   grcKey: "owasp_asvs" },
  iso27034:     { label: "ISO 27034",       grcKey: "iso27034" },
};

// ── Built-in BM25 retriever ────────────────────────────────────────
const STOP = new Set("a an the and or of to in on for with is are be by this that it as at from use used using make sure".split(" "));
const tokenize = t => String(t || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").split(" ").filter(w => w.length > 2 && !STOP.has(w));

const INDEX = {};
for (const [fw, controls] of Object.entries(CATALOG)) {
  const docs = Object.entries(controls).map(([id, c]) => {
    const toks = tokenize(`${c.title} ${c.title} ${c.description} ${(c.keywords || []).join(" ")}`);
    const tf = {};
    for (const w of toks) tf[w] = (tf[w] || 0) + 1;
    return { id, c, tf, len: toks.length };
  });
  const df = {};
  for (const d of docs) for (const w of Object.keys(d.tf)) df[w] = (df[w] || 0) + 1;
  const avg = docs.reduce((a, d) => a + d.len, 0) / Math.max(docs.length, 1);
  INDEX[fw] = { docs, df, avg, N: docs.length };
}

function bm25(fw, query, cwe, k = 3) {
  const ix = INDEX[fw];
  if (!ix) return [];
  const q = [...new Set(tokenize(query))];
  const k1 = 1.4, b = 0.75;
  const scored = ix.docs.map(d => {
    let s = 0;
    for (const w of q) {
      const f = d.tf[w];
      if (!f) continue;
      const idf = Math.log(1 + (ix.N - ix.df[w] + 0.5) / (ix.df[w] + 0.5));
      s += idf * (f * (k1 + 1)) / (f + k1 * (1 - b + b * d.len / ix.avg));
    }
    if (cwe && (d.c.cwe || []).includes(cwe)) s += 4;                // control explicitly lists this CWE
    for (const kw of d.c.keywords || []) if (query.toLowerCase().includes(kw)) s += 1.5;
    return { id: d.id, title: d.c.title, group: d.c.group, description: d.c.description, score: s };
  }).filter(x => x.score > 0).sort((a, b2) => b2.score - a.score).slice(0, k);
  const top = scored[0]?.score || 1;
  return scored.map(x => ({ ...x, score: Math.round((x.score / top) * 100) / 100, source: "local-bm25" }));
}

// ── Python RAG service (if running) ────────────────────────────────
let ragHealth = { ok: false, at: 0 };
export async function ragOnline() {
  if (Date.now() - ragHealth.at < 30000) return ragHealth.ok;
  try {
    const r = await fetch(`${RAG_BASE()}/health`, { signal: AbortSignal.timeout(2500) });
    ragHealth = { ok: r.ok, at: Date.now() };
  } catch { ragHealth = { ok: false, at: Date.now() }; }
  return ragHealth.ok;
}

async function ragRetrieve(fw, text, k = 3) {
  const r = await fetch(`${RAG_BASE()}/map/${fw}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ finding: text, top_k: k }), signal: AbortSignal.timeout(20000),
  });
  if (!r.ok) throw new Error(`RAG ${r.status}`);
  const data = await r.json();
  return (data.controls || []).map(c => ({
    id: c.control_id, title: c.title, group: c.group || c.function || c.domain || c.family || c.chapter || c.ig_level,
    description: CATALOG[fw]?.[c.control_id]?.description || "", score: c.confidence ?? null, source: "rag-service",
  }));
}

function findingText(f) {
  return [f.title, f.message, f.rule, f.cwe, f.package_name, f.file].filter(Boolean).join(" ");
}

/**
 * Map one finding to all frameworks (+ OWASP Top 10 / MITRE via CWE).
 * @returns {{ frameworks: object, owaspTop10: array, mitre: array, retrieval: string }}
 */
export async function mapFinding(f) {
  const text = findingText(f);
  const rule = mapIssueToGRC({ message: text, rule: f.rule, type: f.type, severity: f.severity }).grc_mapping;
  const useRag = await ragOnline();
  const frameworks = {};

  for (const [fw, meta] of Object.entries(FRAMEWORKS)) {
    let retrieved = [];
    if (useRag) {
      try { retrieved = await ragRetrieve(fw, text, 3); } catch { retrieved = []; }
    }
    if (!retrieved.length) retrieved = bm25(fw, text, f.cwe, 3);

    const ruleIds = (rule[meta.grcKey] || []).filter(id => CATALOG[fw]?.[id]);
    const merged = new Map();
    for (const id of ruleIds) {
      const c = CATALOG[fw][id];
      merged.set(id, { id, title: c.title, group: c.group, description: c.description, score: 1, source: "rule" });
    }
    for (const r of retrieved) if (!merged.has(r.id)) merged.set(r.id, r);
    frameworks[fw] = { label: meta.label, controls: [...merged.values()].slice(0, 3) };
  }

  const threat = f.cwe ? resolveThreatMapping(f.cwe) : null;
  return {
    frameworks,
    owaspTop10: threat?.owasp || [],
    mitre: threat?.mitre || [],
    retrieval: useRag ? "RAG service (embeddings + ChromaDB)" : "Built-in retriever (BM25 over framework controls)",
  };
}

/**
 * Write the recommendation for one finding from the retrieved controls.
 * Uses Gemini when configured (retrieval-augmented generation), otherwise a template.
 */
export async function recommend(f, mapping, fixPlan, { useLLM = true } = {}) {
  const top = Object.values(mapping.frameworks)
    .flatMap(x => x.controls.slice(0, 1).map(c => ({ fw: x.label, ...c })));

  if (useLLM && isGeminiConfigured()) {
    const context = top.map(c => `- ${c.fw} ${c.id} "${c.title}": ${String(c.description).slice(0, 300)}`).join("\n");
    const prompt = `You are a security consultant writing one recommendation for a compliance report.
Finding: ${f.title || f.message}
Tool: ${f.tool}; Severity: ${f.severity}; CWE: ${f.cwe || "n/a"}; Location: ${f.url || `${f.file || ""}${f.line ? `:${f.line}` : ""}`}
${f.evidence ? `Code evidence:\n${String(f.evidence).slice(0, 600)}\n` : ""}
Relevant controls retrieved from the knowledge base:
${context}

Write 3-5 sentences in plain English: what to change in this code/config, why it matters for the business,
and which of the retrieved controls it satisfies (cite their IDs). Do not invent other control IDs.`;
    try {
      return { text: await askLLM(prompt), source: `Gemini + ${mapping.retrieval}` };
    } catch (err) {
      console.warn("⚠ Gemini recommendation failed, using template:", err.message);
    }
  }

  const cites = top.slice(0, 4).map(c => `${c.id} (${c.title})`).join("; ");
  const first = fixPlan.toolAdvice
    ? `${fixPlan.toolAdviceSource} advises: ${fixPlan.toolAdvice.split("\n").filter(Boolean)[0].slice(0, 300)}`
    : fixPlan.steps.find(st => !/^(Locate|Open) /.test(st)) || fixPlan.steps[0];
  const text = `${fixPlan.summary} ${first} ` +
    `Doing this closes the gap against ${cites}. ` +
    `Priority ${fixPlan.priority}, target within ${fixPlan.slaDays} days. ${fixPlan.verification}`;
  return { text, source: `Template + ${mapping.retrieval}` };
}
