/**
 * ragService.js
 * Node.js client for the Python NIST CSF RAG microservice (port 5000).
 * Provides mapFindingToNIST() and submitFeedback() for use in routes.
 */

import axios from "axios";

const RAG_BASE = process.env.RAG_SERVICE_URL || "http://localhost:5000";

const ragClient = axios.create({
    baseURL: RAG_BASE,
    timeout: 60000, // scans can take a moment on first load (model init)
    headers: { "Content-Type": "application/json" },
});

/**
 * Map a single SonarQube finding text to NIST CSF 2.0 controls.
 *
 * @param {string} findingText - e.g. "Hardcoded password found in AuthService.java:42"
 * @param {number} topK        - how many controls to return (default 5)
 * @returns {Promise<Array>}   - array of { control_id, function, category, title, confidence }
 */
export async function mapFindingToNIST(findingText, topK = 5) {
    const { data } = await ragClient.post("/map", {
        finding: findingText,
        top_k: topK,
    });
    return data.controls;
}

/**
 * Map multiple SonarQube findings in one call.
 * Sends them concurrently (Promise.allSettled) for speed.
 *
 * @param {string[]} findings - array of finding strings
 * @param {number}   topK
 * @returns {Promise<Array>}  - array of { finding, controls }
 */
export async function mapFindingsBatch(findings, topK = 3) {
    const results = await Promise.allSettled(
        findings.map((f) => mapFindingToNIST(f, topK))
    );

    return findings.map((finding, i) => ({
        finding,
        controls:
            results[i].status === "fulfilled" ? results[i].value : [],
        error:
            results[i].status === "rejected"
                ? results[i].reason?.message
                : null,
    }));
}

/**
 * Submit a human-confirmed mapping to improve future predictions.
 *
 * @param {string} findingText - original finding text
 * @param {string} controlId   - confirmed NIST CSF 2.0 control ID (e.g. "PR.DS-01")
 * @param {string} source      - "human" or "auto"
 */
export async function submitFeedback(findingText, controlId, source = "human") {
    const { data } = await ragClient.post("/feedback", {
        finding_text: findingText,
        control_id: controlId,
        source,
    });
    return data;
}

/**
 * Trigger retraining of the RAG model with all stored feedback.
 */
export async function triggerRetrain() {
    const { data } = await ragClient.post("/retrain");
    return data;
}

/**
 * Get stats from both the index and feedback store.
 */
export async function getRagStats() {
    const { data } = await ragClient.get("/stats");
    return data;
}

/**
 * Check if the RAG service is reachable.
 */
export async function checkRagHealth() {
    try {
        const { data } = await ragClient.get("/health");
        return { online: true, ...data };
    } catch {
        return { online: false, indexed_documents: 0 };
    }
}

/**
 * Get all available NIST CSF 2.0 controls (for frontend dropdowns).
 */
export async function listNISTControls() {
    const { data } = await ragClient.get("/controls");
    return data;
}
