from transformers import pipeline
from langchain_community.llms import HuggingFacePipeline
from langchain_core.tools import Tool
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate

from src.tools import (
    cve_context,
    exploit_lookup,
    mitigation,
    cvss_score
)

llm_pipeline = pipeline(
    "text-generation",
    model="google/flan-t5-base",
    max_new_tokens=256
)

llm = HuggingFacePipeline(pipeline=llm_pipeline)

tools = [
    Tool(name="CVE_Context", func=cve_context, description="Get CVE details"),
    Tool(name="Exploit_Lookup", func=exploit_lookup, description="Check exploits"),
    Tool(name="Mitigation", func=mitigation, description="Suggest mitigation"),
    Tool(name="CVSS_Score", func=cvss_score, description="Verify CVSS score"),
]

prompt = PromptTemplate.from_template(
    """You are a cybersecurity assistant.

You have access to these tools:
{tools}

Use them to answer the query.

Question: {input}
Thought:{agent_scratchpad}
"""
)

agent = create_react_agent(llm, tools, prompt)

agent = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True
)
