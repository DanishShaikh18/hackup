"""
SOCentinel — Groq LLM Client.
Simple wrapper around Groq SDK for Llama 3.3 inference.
"""

import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")


def call_groq(system_prompt: str, user_message: str, model: str = "llama-3.3-70b-versatile") -> str | None:
    """
    Call Groq API with a system prompt and user message.

    Args:
        system_prompt: System-level instruction.
        user_message: User-level message content.
        model: Groq model name.

    Returns:
        Response text string, or None on failure.
    """
    try:
        client = Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            temperature=0.1,
            max_tokens=2048,
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"[groq_client] Error: {e}")
        return None
