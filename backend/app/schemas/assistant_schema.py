from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class ChatMessage(BaseModel):
    role: str  # "user" or "assistant"
    content: str

class ChatRequest(BaseModel):
    message: str = Field(..., description="User prompt or cybersecurity question")
    scan_context: Optional[Dict[str, Any]] = None  # Current scan results to explain
    history: Optional[List[ChatMessage]] = []

class ChatResponse(BaseModel):
    reply: str
    source: str  # "gemini" or "expert_rules"
