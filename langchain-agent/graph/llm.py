"""
LLM factory for graph nodes — dual-engine routing for consensus validation.
"""
import os
import json
import re
import logging
from typing import Any, Dict, Optional

from langchain_openai import ChatOpenAI
from langchain_mistralai import ChatMistralAI

log = logging.getLogger(__name__)

OPENAI_API_KEY  = os.getenv("OPENAI_API_KEY", "")
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY", "")


def get_primary_llm():
    """GPT-4o if available, else Mistral-large."""
    if OPENAI_API_KEY:
        return ChatOpenAI(model="gpt-4o", api_key=OPENAI_API_KEY, temperature=0)
    if MISTRAL_API_KEY:
        return ChatMistralAI(model="mistral-large-latest", api_key=MISTRAL_API_KEY, temperature=0)
    raise ValueError("No LLM API key configured")


def get_consensus_llm():
    """Independent secondary model for consensus validation (must differ from primary)."""
    if OPENAI_API_KEY and MISTRAL_API_KEY:
        return ChatMistralAI(model="mistral-large-latest", api_key=MISTRAL_API_KEY, temperature=0)
    if OPENAI_API_KEY:
        return ChatOpenAI(model="gpt-4o-mini", api_key=OPENAI_API_KEY, temperature=0)
    if MISTRAL_API_KEY:
        return ChatMistralAI(model="mistral-small-latest", api_key=MISTRAL_API_KEY, temperature=0)
    raise ValueError("No LLM API key configured")


def get_fast_llm():
    """Fast model for triage / classification — gpt-4o-mini or mistral-small."""
    if OPENAI_API_KEY:
        return ChatOpenAI(model="gpt-4o-mini", api_key=OPENAI_API_KEY, temperature=0)
    if MISTRAL_API_KEY:
        return ChatMistralAI(model="mistral-small-latest", api_key=MISTRAL_API_KEY, temperature=0)
    raise ValueError("No LLM API key configured")


def parse_json_response(text: str, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Extract JSON object from LLM response, tolerant of markdown fences."""
    if default is None:
        default = {}
    if not text:
        return default
    text = text.strip()
    # Strip markdown fences
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    # Find JSON object
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return default
    try:
        return json.loads(match.group())
    except Exception as e:
        log.warning(f"[parse_json_response] failed: {e}")
        return default
