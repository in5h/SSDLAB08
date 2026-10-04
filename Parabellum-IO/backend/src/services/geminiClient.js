// src/services/geminiClient.js
// Gemini client used for AI remediation advice (POST /api/risk/ai-advice).
import { GoogleGenerativeAI } from "@google/generative-ai";

const MODEL_NAME = process.env.GEMINI_MODEL || "gemini-2.5-flash-lite";

let model = null;

/** True when a real-looking GEMINI_API_KEY is configured. */
export function isGeminiConfigured() {
  const key = process.env.GEMINI_API_KEY || "";
  return key.length > 0 && !key.startsWith("your_");
}

function getModel() {
  if (!model) {
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    model = genAI.getGenerativeModel({ model: MODEL_NAME });
    console.log(`✅ Gemini client initialized with ${MODEL_NAME}`);
  }
  return model;
}

/**
 * Low-level helper to call Gemini with a plain text prompt.
 */
export async function askLLM(prompt) {
  if (!isGeminiConfigured()) {
    throw new Error("GEMINI_API_KEY is not set in backend/.env.");
  }
  const result = await getModel().generateContent(prompt);
  return result.response.text().trim();
}
