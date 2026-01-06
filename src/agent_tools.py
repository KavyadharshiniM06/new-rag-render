from langchain.agents import Tool, initialize_agent
from langchain_community.llms import HuggingFacePipeline
from transformers import pipeline

from src.agent_tools import (
    cve_context_tool,
    exploit_lookup_tool,
    patch_suggestion_tool,
    cvss_verification_tool
)

llm_pipeline = pipeline(
    "text-generation",
    model="google/flan-t5-base",
    max_new_tokens=256
)

llm = HuggingFacePipeline(pipeline=llm_pipeline)

tools = [
    Tool(
        name="CVE Context",
        func=cve_context_tool,
        description="Retrieve CVE details from vector database"
    ),
    Tool(
        name="Exploit Lookup",
        func=exploit_lookup_tool,
        description="Check whether public exploits exist"
    ),
    Tool(
        name="Patch Suggestion",
        func=patch_suggestion_tool,
        description="Suggest mitigation or patch"
    ),
    Tool(
        name="CVSS Verification",
        func=cvss_verification_tool,
        description="Verify CVSS severity"
    ),
]

agent = initialize_agent(
    tools=tools,
    llm=llm,
    agent="zero-shot-react-description",
    verbose=True
)
