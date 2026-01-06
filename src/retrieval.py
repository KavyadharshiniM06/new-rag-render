import chromadb
from sentence_transformers import SentenceTransformer
from collections import defaultdict
import os

CHROMA_DIR = "chroma_db"
COLLECTION_NAME = "cve_rag"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

embedding_model = SentenceTransformer(EMBEDDING_MODEL)

client = chromadb.PersistentClient(path=CHROMA_DIR)
collection = client.get_or_create_collection(name=COLLECTION_NAME)

def query_cve(query_text: str, top_k: int = 5, severity: str | None = None):
    query_embedding = embedding_model.encode(query_text).tolist()

    where_clause = (
        {"severity": {"$eq": severity.upper()}}
        if severity else None
    )

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=top_k,
        where=where_clause,
        include=["documents", "metadatas"]
    )

    if not results["documents"] or not results["documents"][0]:
        return {}

    grouped = defaultdict(lambda: {
        "severity": None,
        "sections": {}
    })

    for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
        cve_id = meta["cve_id"]
        grouped[cve_id]["severity"] = meta.get("severity")
        grouped[cve_id]["sections"][meta.get("section")] = doc

    return dict(grouped)
