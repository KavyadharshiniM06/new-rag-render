# src/hf_llm_wrapper.py
from huggingface_hub import InferenceClient
import re, json
from src.retrieval import query_cve

# Initialize Hugging Face Inference Client
client = InferenceClient(token="HF_API_KEY")  # <-- Replace with your HF token

def enrich_cve_hf(prompt: str) -> dict:
    response = client.text_generation(
        model="google/flan-t5-small",
        inputs=prompt,
        max_new_tokens=128
    )
    output_text = response[0]["generated_text"]

    # Attempt to extract JSON from LLM output
    match = re.search(r"\{.*\}", output_text, re.DOTALL)
    try:
        return json.loads(match.group())
    except:
        return {"attack_scenario": "Not specified", "mitigation": "Not specified"}

# CVE Chain
class HF_CVEChain:
    def __init__(self):
        self.retriever = query_cve

    def enrich_cve(self, cve_id, data):
        prompt = f"CVE ID: {cve_id}\nSeverity: {data['severity']}\n"
        for section, content in data["sections"].items():
            prompt += f"{section}: {content['content']}\n"
        prompt += "\nReturn ONLY valid JSON with keys: attack_scenario, mitigation."

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
