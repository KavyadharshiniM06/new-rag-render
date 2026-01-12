# src/hf_llm_wrapper.py
import os
import re
import json
from huggingface_hub import InferenceClient
from src.retrieval import query_cve

# HF client (lightweight, no local model)
client = InferenceClient(
    model="google/flan-t5-base",
    token=os.environ["HF_API_KEY"]
)

def extract_json(text: str):
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group())
    except:
        return None

def enrich_cve_hf(prompt: str) -> dict:
    output_text = client.text_generation(
        prompt,
        max_new_tokens=120,
        temperature=0.0
    )

    parsed = extract_json(output_text)
    if parsed:
        return parsed

    # intelligent fallback (VERY IMPORTANT)
    return {
        "attack_scenario": output_text.strip(),
        "mitigation": "Apply vendor patches, update affected software, and enforce input validation."
    }

class HF_CVEChain:
    def __init__(self):
        self.retriever = query_cve

    def enrich_cve(self, cve_id, data):
        prompt = f"""
You are a cybersecurity analyst.

CVE ID: {cve_id}
Severity: {data['severity']}

Context:
"""
        for section, content in data["sections"].items():
            prompt += f"{section}: {content['content']}\n"

        prompt += """
Return ONLY valid JSON:
{
  "attack_scenario": "...",
  "mitigation": "..."
}
"""

        return enrich_cve_hf(prompt)

    def invoke(self, query: str, top_k: int = 2) -> dict:
        results = self.retriever(query, top_k=top_k)
        enriched_results = {}

        for cve_id, data in results.items():
            enriched = self.enrich_cve(cve_id, data)
            enriched_results[cve_id] = {
                "severity": data["severity"],
                "sections": {**data["sections"], **enriched}
            }

        return enriched_results
