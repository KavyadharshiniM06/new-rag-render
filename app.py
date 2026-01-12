from fastapi import FastAPI, Query
from src.llm_wrapper import LocalCVEChain

app = FastAPI(
    title="CVE RAG Intelligence API",
    description="Semantic CVE search with local LLM enrichment",
    version="1.0.0"
)

chain = LocalCVEChain()

@app.get("/")
def health():
    return {"status": "ok"}

@app.get("/search")
def search_cve(
    q: str = Query(..., description="Search query"),
    top_k: int = Query(5, ge=1, le=10)
):
    results = chain.invoke(q, top_k=top_k)
    return results

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # Render sets $PORT
    uvicorn.run("app:app", host="0.0.0.0", port=port)
