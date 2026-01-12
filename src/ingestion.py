import json
import chromadb
from sentence_transformers import SentenceTransformer

DATA_PATH = "data/cve/cve_dataset.json"
CHROMA_DIR = "chroma_db"
COLLECTION_NAME = "cves"

model = SentenceTransformer("all-MiniLM-L6-v2")

client = chromadb.PersistentClient(
    path=CHROMA_DIR
)

collection = client.get_or_create_collection(
    name=COLLECTION_NAME,
    metadata={"hnsw:space": "cosine"}
)

with open(DATA_PATH, "r", encoding="utf-8") as f:
    cves = json.load(f)

documents = []
metadatas = []
ids = []

for cve in cves:
    cve_id = cve["id"]
    severity = cve["severity"]
    sections = cve["sections"]

    for section_name, content in sections.items():
        if not content:
            continue

        if isinstance(content, list):
            content = "\n".join(content)

        doc_id = f"{cve_id}_{section_name}"

        documents.append(content)
        metadatas.append({
            "cve_id": cve_id,
            "severity": severity,
            "section": section_name
        })
        ids.append(doc_id)

embeddings = model.encode(documents, show_progress_bar=True)

collection.add(
    documents=documents,
    metadatas=metadatas,
    embeddings=embeddings.tolist(),
    ids=ids
)

print(f"[+] Ingested {len(ids)} CVE sections into ChromaDB (persistent)")
