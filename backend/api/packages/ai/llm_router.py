import os
import json
import re
import time
import logging
from typing import Optional

import httpx
from groq import Groq

logger = logging.getLogger(__name__)

OPENROUTER_BASE = "https://openrouter.ai/api/v1"
OPENROUTER_KEY  = os.getenv("OPENROUTER_API_KEY", "")
GROQ_KEY        = os.getenv("GROQ_API_KEY", "")

OPENROUTER_MODELS = [
    # New Free models provided by user
    "nvidia/nemotron-3-super:free",
    "arcee-ai/trinity-large-preview:free",
    "z-ai/glm-4.5-air:free",
    "openai/gpt-oss-120b:free",
    "minimax/minimax-m2.5:free",
    "google/gemma-4-31b:free",
    "nvidia/nemotron-3-nano-30b-a3b:free",
    "nvidia/nemotron-nano-9b-v2:free",
    
    # Existing stable models
    "qwen/qwen-2.5-coder-32b",
    "meta-llama/llama-3.3-70b-instruct",
]

GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "mixtral-8x7b-32768",
]


class LLMRouter:
    """
    Tries OpenRouter models in order.
    Falls back to Groq if all OpenRouter fail.
    """

    def __init__(self):
        self._extra_providers = []

    def add_provider(self, fn):
        self._extra_providers.append(fn)

    def chat(
        self,
        messages: list,
        system: str = "",
        max_tokens: int = 1500,
        temperature: float = 0.2,
    ) -> str:
        last_err = None

        # 1. Try OpenRouter models in order
        if OPENROUTER_KEY:
            for model in OPENROUTER_MODELS:
                try:
                    return self._openrouter(
                        model, messages, system,
                        max_tokens, temperature,
                    )
                except Exception as e:
                    logger.warning(
                        f"OpenRouter {model} failed: "
                        f"{str(e)[:80]}"
                    )
                    last_err = e
                    time.sleep(0.3)

        # 2. Try Groq models in order
        if GROQ_KEY:
            for model in GROQ_MODELS:
                try:
                    return self._groq(
                        model, messages, system,
                        max_tokens, temperature,
                    )
                except Exception as e:
                    logger.warning(
                        f"Groq {model} failed: "
                        f"{str(e)[:80]}"
                    )
                    last_err = e
                    time.sleep(0.3)

        # 3. Try extra providers
        for provider_fn in self._extra_providers:
            try:
                return provider_fn(
                    messages, system, max_tokens
                )
            except Exception as e:
                last_err = e

        raise RuntimeError(
            f"All LLM providers failed. "
            f"Last error: {last_err}"
        )

    def chat_json(
        self,
        messages: list,
        system: str = "",
        max_tokens: int = 2000,
    ) -> dict:
        raw = self.chat(messages, system, max_tokens)
        return self._parse_json(raw)

    def _openrouter(
        self,
        model: str,
        messages: list,
        system: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        msgs = []
        if system:
            msgs.append({
                "role":    "system",
                "content": system,
            })
        msgs.extend(messages)

        with httpx.Client(timeout=45) as client:
            resp = client.post(
                f"{OPENROUTER_BASE}/chat/completions",
                headers={
                    "Authorization":
                        f"Bearer {OPENROUTER_KEY}",
                    "HTTP-Referer":
                        "https://shieldsentinel.io",
                    "X-Title": "ShieldSentinel",
                    "Content-Type": "application/json",
                },
                json={
                    "model":       model,
                    "messages":    msgs,
                    "max_tokens":  max_tokens,
                    "temperature": temperature,
                },
            )
            resp.raise_for_status()
            data = resp.json()

            if "error" in data:
                raise RuntimeError(
                    data["error"].get(
                        "message", "Unknown error"
                    )
                )

            return (
                data["choices"][0]
                    ["message"]["content"]
            )

    def _groq(
        self,
        model: str,
        messages: list,
        system: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        client = Groq(api_key=GROQ_KEY)
        msgs = []
        if system:
            msgs.append({
                "role":    "system",
                "content": system,
            })
        msgs.extend(messages)

        resp = client.chat.completions.create(
            model=model,
            messages=msgs,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=40,
        )
        return resp.choices[0].message.content

    def _parse_json(self, raw: str) -> dict:
        clean = raw.strip()

        # Strip markdown code fences
        if "```json" in clean:
            clean = clean.split("```json")[-1].split("```")[0]
        elif "```" in clean:
            clean = clean.split("```")[-1].split("```")[0]
        clean = clean.strip()

        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            match = re.search(
                r"\{.*\}", clean, re.DOTALL
            )
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass
            return {
                "error": "JSON parse failed",
                "raw":   raw[:200],
            }
