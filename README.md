<<<<<<< HEAD
---
title: CVE RAG Security Agent
emoji: 🛡️
colorFrom: gray
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---
---

# 🔐 CVE Security Agent (RAG Chatbot)

A **FastAPI-based cybersecurity agent** that fetches, embeds, and queries CVE data to provide **exploit insights, attack scenarios, mitigations, patch suggestions, and CVSS verification** using a retrieval-augmented generation (RAG) approach.

---

## Features

* ✅ **Automated CVE collection** from NVD API
* ✅ **Embedding and vectorization** using ChromaDB + `all-MiniLM-L6-v2`
* ✅ **Fast retrieval of CVE details** (description, severity, attack scenario, affected products, references, mitigation)
* ✅ **Summarization and patch suggestions** via LLM
* ✅ **Verify CVSS scores** programmatically
* ✅ **LangChain Agent Support** – multi-step reasoning:

  * Check CVE → fetch exploit → summarize → suggest patch → verify CVSS
* ✅ **FastAPI endpoint** for programmatic queries
* ✅ **Docker-ready deployment** for Hugging Face Spaces or local servers

---

## Project Structure

```
My_CVE_Chatbot/
│
├─ src/
│   ├─ datacollection.py      
│   ├─ ingestion.py            
│   ├─ retrieval.py                          
│   └─ agent.py
|   └─ agent_tools.py           
├─ app.py 
├─ requirements.txt
├─ Dockerfile
└─ README.md


```

---

## Setup & Deployment

### 1. Clone the repository

```bash
git clone https://huggingface.co/spaces/<username>/<repo-name>
cd <repo-name>
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Fetch CVE data and build the vector database

```bash
python src/datacollection.py
python src/ingestion.py
```

### 4. Run FastAPI server locally

```bash
uvicorn src.app:app --host 0.0.0.0 --port 8000
```

* Open [http://localhost:8000/docs](http://localhost:8000/docs) to interact with the API using Swagger UI.

### 5. Example API Request

```bash
curl -X POST http://localhost:8000/ask \
     -H "Content-Type: application/json" \
     -d '{"question":"Explain CVE-2023-12345 and suggest mitigation."}'
```

---

## LangChain Multi-Step Agent Workflow

The project also includes a **LangChain-based agent** that can handle:

1. **Check CVE:** Retrieve CVE details from the vector database
2. **Fetch Exploit:** Search known exploits for the CVE
3. **Summarize:** Provide a concise summary of the vulnerability
4. **Suggest Patch:** Recommend remediation/patches
5. **Verify CVSS:** Cross-check CVSS score for accuracy

This allows a **full end-to-end security reasoning pipeline** in a single agent workflow.

---

## Deployment on Hugging Face Spaces

1. Make sure `Dockerfile` and `requirements.txt` are present.
2. Push to your Space:

```bash
git add .
git commit -m "Deploy FastAPI CVE security agent with LangChain agent"
git push
```

* Hugging Face will automatically:

  * Build the Docker image
  * Install dependencies
  * Launch the FastAPI app

---

## Technologies Used

* **FastAPI** – lightweight web API framework
* **ChromaDB** – vector database for CVE embeddings
* **Sentence Transformers** – generate embeddings for semantic search
* **Transformers / Mistral-7B-Instruct** – LLM for summarization & patch suggestions
* **LangChain** – multi-step agent workflow
* **NVD API** – source of CVE information
* **Docker** – containerized deployment

---

## Future Enhancements

* 🔹 Integrate **real-time exploit feeds**
* 🔹 Add **interactive dashboards** for CVE trends and analytics
* 🔹 Extend **LangChain agent reasoning** for automated CVSS validation
* 🔹 Add **automated email alerts** for high-severity CVEs

---
=======
# new-rag-render
>>>>>>> 75e7d9bca3f14a67a62059d70433ec9eb8875594
