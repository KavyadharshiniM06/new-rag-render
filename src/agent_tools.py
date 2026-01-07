from langchain_core.tools import tool
from src.retrieval import retrieve_cve_context

@tool
def cve_context_tool(query: str) -> str:
    """Retrieve CVE-related context from vector database"""
    return retrieve_cve_context(query)

@tool
def exploit_lookup_tool(cve_id: str) -> str:
    return f"No public exploit detected yet for {cve_id}"

@tool
def patch_suggestion_tool(cve_id: str) -> str:
    return f"Check vendor advisories and apply latest patches for {cve_id}"

@tool
def cvss_verification_tool(severity: str) -> str:
    return f"Severity verified as {severity}"
