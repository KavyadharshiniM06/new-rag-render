from fastapi import FastAPI
from pydantic import BaseModel
from src.agent import agent

app = FastAPI(title="CVE RAG Security Agent")

class QueryRequest(BaseModel):
    question: str

@app.get("/")
def health():
    return {"status": "CVE Agent running"}

@app.post("/analyze")
def analyze_cve(request: QueryRequest):
    response = agent.invoke(
        f"""
        Analyze the following CVE request:
        1. Retrieve CVE details
        2. Identify potential exploits
        3. Summarize impact
        4. Suggest patch or mitigation
        5. Verify CVSS severity

        Query: {request.question}
        """
    )
    return {"analysis": response}

