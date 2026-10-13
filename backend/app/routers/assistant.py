from fastapi import APIRouter
from ..schemas.assistant_schema import ChatRequest, ChatResponse
from ..engines.ai_assistant import ask_cyber_assistant

router = APIRouter(prefix="/api/assistant", tags=["AI Cyber Assistant"])

@router.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    result = await ask_cyber_assistant(
        user_message=req.message,
        scan_context=req.scan_context,
        history=[msg.model_dump() for msg in req.history] if req.history else []
    )
    return result
