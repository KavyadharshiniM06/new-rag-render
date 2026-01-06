import os
import json
import chromadb
from sentence_transformers import SentenceTransformer

DATA_PATH = "data/cve_dataset.json"
CHROMA_DIR = "chroma_db"
COLLECTION_NAME = "cve_rag"

embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
client = chromadb.PersistentClient(path=CHROMA_DIR)
collection = client.get_or_create_collection(name=COLLECTION_NAME)

with open(DATA_PATH, "r", encoding="utf-8") as f:
    cve_data = json.load(f)

for cve in cve_data:
    cve_id = cve["id"]
    severity = cve["severity"]
    sections = cve["sections"]

    text_sections = {
        "description": sections.get("description", ""),
        "attack_scenario": sections.get("Attack Scenario", ""),
        "mitigation": " ".join(sections.get("Mitigation", []))
    }

    for section, content in text_sections.items():
        if not content.strip():
            continue

        embedding = embedding_model.encode(content).tolist()

        collection.add(
            documents=[content],
            embeddings=[embedding],
            metadatas=[{
                "cve_id": cve_id,
                "severity": severity,
                "section": section
            }],
            ids=[f"{cve_id}_{section}"]
        )

print("Ingestion complete")
print("Total vectors:", collection.count())
