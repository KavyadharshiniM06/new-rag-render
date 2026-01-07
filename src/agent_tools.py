from transformers import pipeline
from langchain_community.llms import HuggingFacePipeline
from langchain_core.tools import Tool
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate

# Your actual functions
from src.agent_tools import (
    cve_context_tool,
    exploit_lookup_tool,
    patch_suggestion_tool,
    cvss_verification_tool
)

# LLM setup
llm_pipeline = pipeline(
    "text-generation",
    model="google/flan-t5-base",
    max_new_tokens=256
)
llm = HuggingFacePipeline(pipeline=llm_pipeline)

# Tools setup
tools = [
    Tool(name="CVE Context", func=cve_context_tool, description="Retrieve CVE details from vector database"),
    Tool(name="Exploit Lookup", func=exploit_lookup_tool, description="Check whether public exploits exist"),
    Tool(name="Patch Suggestion", func=patch_suggestion_tool, description="Suggest mitigation or patch"),
    Tool(name="CVSS Verification", func=cvss_verification_tool, description="Verify CVSS severity"),
]

# Optional: Prompt template
prompt = PromptTemplate.from_template(
    """You are a cybersecurity agent.
You have access to these tools:
{tools}

Use them to answer the query.
Question: {input}
Thought: {agent_scratchpad}"""
)

# Create the agent
agent_instance = create_react_agent(
    llm=llm,
    tools=tools,
    prompt=prompt
)

# Wrap with executor for easy use
agent = AgentExecutor(
    agent=agent_instance,
    tools=tools,
    verbose=True
)
