import torch
import json
import re
from transformers import pipeline
from retrieval import query_cve

device = 0 if torch.cuda.is_available() else -1

llm = pipeline(
    "text2text-generation",
    model="google/flan-t5-base",
    device=device
)

def extract_json(text):
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group())
    except:
        return None

class LocalCVEChain:
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
Return ONLY valid JSON.
Format:
{
  "attack_scenario": "...",
  "mitigation": "..."
}
"""

        try:
            output = llm(prompt, max_new_tokens=128, do_sample=False)[0]["generated_text"]
            parsed = extract_json(output)
            if not parsed:
                raise ValueError
            return parsed
        except:
            text = output.strip() if 'output' in locals() else ""

            # Try to recover JSON-like content
            recovered = extract_json("{" + text + "}")
            if recovered:
                return recovered

            return {
        "attack_scenario": text[:400] if text else "Not specified",
        "mitigation": "Apply vendor patches, update affected software, and enforce input validation."
                }

    def invoke(self, query, top_k=5):
        results = self.retriever(query, top_k=top_k)
        enriched_results = {}

        for cve_id, data in results.items():
            enriched = self.enrich_cve(cve_id, data)
            enriched_results[cve_id] = {
                "severity": data["severity"],
                "sections": {**data["sections"], **enriched}
            }

        return enriched_results
