"""
Learning Hub AI Chat Router

Provides AI-powered Q&A for learning pages using Gemini.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import os

from backend.core.config import settings

router = APIRouter(prefix="/learn", tags=["Learn Chat"])


class ChatMessage(BaseModel):
    role: str
    content: str


class LearnChatRequest(BaseModel):
    message: str
    page_title: str
    page_context: str
    conversation_history: Optional[List[ChatMessage]] = []


class LearnChatResponse(BaseModel):
    response: str


@router.post("/chat", response_model=LearnChatResponse)
async def learn_chat(request: LearnChatRequest):
    """
    AI-powered chat for learning pages.
    Uses the page context to provide relevant answers.
    """
    try:
        # Import Gemini
        from google import genai
        
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise HTTPException(
                status_code=500,
                detail="AI API key not configured"
            )
        
        client = genai.Client(api_key=api_key)
        
        # Build the system prompt with page context
        system_prompt = f"""You are a helpful cybersecurity learning assistant embedded in the VRAgent security scanner application.

You are currently helping a user learn about: **{request.page_title}**

Here is the context from the current learning page they are viewing:
---
{request.page_context[:8000]}  
---

Your role:
1. Answer questions about the topic based on the page content and your knowledge
2. Provide clear, educational explanations suitable for security learners
3. Give practical examples when helpful
4. Relate concepts to real-world security scenarios
5. Be encouraging and supportive of their learning journey

Guidelines:
- Keep responses concise but informative (2-4 paragraphs max unless more detail is requested)
- Use bullet points for lists
- Include code examples when relevant (with proper formatting)
- If asked about something not related to the page topic, you can still help but mention you're going beyond the current page
- Always maintain a focus on cybersecurity education
- Be accurate - if you're not sure about something, say so

Respond in a conversational, helpful tone."""

        # Build conversation messages
        messages = []
        
        # Add conversation history
        for msg in request.conversation_history[-10:]:  # Keep last 10 messages for context
            messages.append({
                "role": "user" if msg.role == "user" else "model",
                "parts": [{"text": msg.content}]
            })
        
        # Add current message
        messages.append({
            "role": "user",
            "parts": [{"text": request.message}]
        })
        
        # Generate response
        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=messages,
            config={
                "system_instruction": system_prompt,
                "temperature": 0.7,
                "max_output_tokens": 1024,
            }
        )
        
        if response.text:
            return LearnChatResponse(response=response.text)
        else:
            return LearnChatResponse(
                response="I apologize, but I couldn't generate a response. Please try rephrasing your question."
            )
            
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="AI module not available. Please check server configuration."
        )
    except Exception as e:
        print(f"Learn chat error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate response: {str(e)}"
        )
