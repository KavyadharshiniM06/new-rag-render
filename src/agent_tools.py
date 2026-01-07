from langchain.agents import create_agent
from langchain_core.prompts import PromptTemplate
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
    max_new_tokens=256,
)

llm = HuggingFacePipeline(pipeline=llm_pipeline)

tools = [
    cve_context_tool,
    exploit_lookup_tool,
    patch_suggestion_tool,
    cvss_verification_tool,
]

prompt = PromptTemplate.from_template(
    """You are a cybersecurity agent.
    You have access to these tools:
    {tools}

    Use them to answer the query.
    Question: {input}
    """
)

agent = create_agent(
    llm=llm,
    tools=tools,
    system_prompt=prompt,
)
