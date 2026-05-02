"""LLM client abstraction for Anthropic, OpenAI, Ollama, and OpenAI-compatible endpoints."""

import os
import re
import time
from dataclasses import dataclass
from typing import Any

@dataclass
class LLMCallResult:
    text: str
    input_tokens: int | None
    output_tokens: int | None
    cached_input_tokens: int | None
    uncached_input_tokens: int | None
    cache_creation_input_tokens: int | None
    cache_read_input_tokens: int | None
    raw_input_tokens: int | None
    wall_time_s: float
    model: str

class LLMClient:
    """Unified interface for Anthropic, OpenAI, Ollama, and OpenAI-compatible endpoints."""

    def __init__(self, provider="anthropic", model=None, base_url=None, api_key=None):
        self.provider = provider
        if provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic()
            self.model = model or "claude-opus-4-5-20251101"
        elif provider == "openai":
            import openai
            self.client = openai.OpenAI()
            self.model = model or "gpt-5.1-codex-mini"
        elif provider == "ollama":
            import openai
            ollama_key = api_key or os.environ.get("OLLAMA_API_KEY", "")
            ollama_url = base_url or "https://ollama.com/v1"
            self.client = openai.OpenAI(base_url=ollama_url, api_key=ollama_key)
            self.model = model or "gemma3"
        elif provider == "openai-compat":
            import openai
            if not base_url:
                raise ValueError("--base-url required for openai-compat provider")
            self.client = openai.OpenAI(base_url=base_url, api_key=api_key or "unused")
            self.model = model or "default"
        else:
            raise ValueError(f"Unknown provider: {provider}")

    _REASONING_MODELS = {
        "gpt-5.1-codex-mini",
        "gpt-5.2-codex",
        "gpt-5.2-codex-mini",
        "o1",
        "o1-mini",
        "o1-preview",
        "o3-mini",
    }

    @staticmethod
    def _nested_get(obj: Any, *keys):
        cur = obj
        for k in keys:
            if cur is None:
                return None
            if isinstance(cur, dict):
                cur = cur.get(k)
            else:
                cur = getattr(cur, k, None)
        return cur

    @staticmethod
    def _normalize_token_count(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, float):
            return int(value)
        return value if isinstance(value, int) else None

    @classmethod
    def _extract_input_token_breakdown(cls, usage, input_total, *, provider=None):
        """Best-effort extraction of cache read/write/uncached token counts."""
        raw_input = cls._normalize_token_count(input_total)
        cache_read = cls._normalize_token_count(
            cls._nested_get(usage, "cache_read_input_tokens")
            or cls._nested_get(usage, "cacheReadInputTokens")
            or cls._nested_get(usage, "input_tokens_details", "cached_tokens")
            or cls._nested_get(usage, "prompt_tokens_details", "cached_tokens")
            or cls._nested_get(usage, "cached_input_tokens")
        )
        cache_creation = cls._normalize_token_count(
            cls._nested_get(usage, "cache_creation_input_tokens")
            or cls._nested_get(usage, "cacheCreationInputTokens")
        )

        if provider == "anthropic" and (
            cache_read is not None or cache_creation is not None
        ):
            total_input = sum(
                value for value in (raw_input, cache_read, cache_creation)
                if isinstance(value, int)
            )
            if raw_input is None and cache_read is None and cache_creation is None:
                total_input = None
            uncached = None
            if raw_input is not None or cache_creation is not None:
                uncached = (raw_input or 0) + (cache_creation or 0)
            return total_input, cache_read, cache_creation, uncached, raw_input

        total_input = raw_input
        uncached = None
        if raw_input is not None:
            if cache_read is not None:
                uncached = max(raw_input - cache_read, 0)
            else:
                uncached = raw_input
        return total_input, cache_read, cache_creation, uncached, raw_input

    def chat(self, messages, max_tokens=16_384, temperature=0.7):
        """Send messages, return LLMCallResult with text, tokens, and timing."""
        effective_max = max_tokens
        if self.provider == "openai":
            model_l = (self.model or "").lower()
            is_reasoning = ("codex" in model_l) or any(
                r in model_l for r in self._REASONING_MODELS
            )
        else:
            is_reasoning = False
        if is_reasoning:

            effective_max = max(max_tokens * 4, 65_536)

        t0 = time.monotonic()
        if self.provider == "anthropic":
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=messages,
            )
            wall_time = time.monotonic() - t0
            usage = getattr(response, "usage", None)
            raw_in = self._nested_get(usage, "input_tokens")
            total_in, cache_read, cache_create, uncached_in, raw_input = (
                self._extract_input_token_breakdown(
                    usage,
                    raw_in,
                    provider="anthropic",
                )
            )
            out_tok = self._normalize_token_count(
                self._nested_get(usage, "output_tokens")
            )
            text = "".join(
                getattr(block, "text", "")
                for block in getattr(response, "content", [])
                if getattr(block, "type", None) == "text" or hasattr(block, "text")
            )
            return LLMCallResult(
                text=text,
                input_tokens=total_in,
                output_tokens=out_tok,
                cached_input_tokens=cache_read,
                uncached_input_tokens=uncached_in,
                cache_creation_input_tokens=cache_create,
                cache_read_input_tokens=cache_read,
                raw_input_tokens=raw_input,
                wall_time_s=round(wall_time, 3),
                model=self.model,
            )
        elif self.provider == "openai":
            create_kwargs = dict(
                model=self.model,
                input=self._to_openai_responses_input(messages),
                max_output_tokens=effective_max,
            )

            if temperature is not None:
                create_kwargs["temperature"] = temperature
            try:
                response = self.client.responses.create(**create_kwargs)
            except Exception as exc:
                if "temperature" in str(exc).lower() and "not supported" in str(exc).lower():
                    create_kwargs.pop("temperature", None)
                    response = self.client.responses.create(**create_kwargs)
                else:
                    raise
            wall_time = time.monotonic() - t0
            try:
                usage = response.usage
                in_tok = usage.input_tokens
                out_tok = usage.output_tokens
            except (AttributeError, TypeError):
                usage = None
                in_tok = out_tok = None
            total_in, cached_tok, cache_create_tok, uncached_tok, raw_in = (
                self._extract_input_token_breakdown(usage, in_tok)
            )

            text = response.output_text or ""
            if not text and hasattr(response, "output"):
                parts = []
                for item in response.output:
                    if hasattr(item, "content") and item.content:
                        for block in item.content:
                            if hasattr(block, "text"):
                                parts.append(block.text)
                    elif hasattr(item, "text"):
                        parts.append(item.text)
                text = "\n".join(parts)

            if not text and hasattr(response, "output"):
                text = repr(response.output)
                print(f"[LLMClient] Warning: model returned no text output "
                      f"(only reasoning/internal items). The model likely ran "
                      f"out of output tokens. Consider using a non-reasoning model "
                      f"or raising the output-token budget in llm_client. "
                      f"(max_output_tokens={effective_max})")
            return LLMCallResult(
                text=text,
                input_tokens=total_in,
                output_tokens=out_tok,
                cached_input_tokens=cached_tok,
                uncached_input_tokens=uncached_tok,
                cache_creation_input_tokens=cache_create_tok,
                cache_read_input_tokens=cached_tok,
                raw_input_tokens=raw_in,
                wall_time_s=round(wall_time, 3),
                model=self.model,
            )
        elif self.provider in ("ollama", "openai-compat"):
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self._to_openai_chat_messages(messages),
                max_tokens=max_tokens,
                temperature=temperature,
            )
            wall_time = time.monotonic() - t0
            try:
                usage = response.usage
                in_tok = usage.prompt_tokens
                out_tok = usage.completion_tokens
            except (AttributeError, TypeError):
                usage = None
                in_tok = out_tok = None
            total_in, cached_tok, cache_create_tok, uncached_tok, raw_in = (
                self._extract_input_token_breakdown(usage, in_tok)
            )
            return LLMCallResult(
                text=response.choices[0].message.content,
                input_tokens=total_in,
                output_tokens=out_tok,
                cached_input_tokens=cached_tok,
                uncached_input_tokens=uncached_tok,
                cache_creation_input_tokens=cache_create_tok,
                cache_read_input_tokens=cached_tok,
                raw_input_tokens=raw_in,
                wall_time_s=round(wall_time, 3),
                model=self.model,
            )

    @staticmethod
    def _to_openai_responses_input(messages):
        out = []
        for msg in messages:
            role = msg["role"]
            content = msg["content"]

            if isinstance(content, list):
                text = "".join(
                    block.get("text", "")
                    for block in content
                    if block.get("type") == "text"
                ).strip()
            else:
                text = str(content).strip()

            block_type = "output_text" if role == "assistant" else "input_text"

            out.append({
                "role": role,
                "content": [{"type": block_type, "text": text}],
            })
        return out

    @staticmethod
    def _to_openai_chat_messages(messages):
        """Convert Anthropic-style messages to OpenAI chat completions format."""
        out = []
        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            if isinstance(content, list):
                text = "".join(
                    block.get("text", "")
                    for block in content
                    if block.get("type") == "text"
                ).strip()
            else:
                text = str(content).strip()
            out.append({"role": role, "content": text})
        return out

def extract_rust_code(response_text):
    """Extract Rust code from LLM response (inside ```rust ... ``` blocks).

    Returns the extracted code, or empty string if no valid code found.
    """
    if not response_text or not response_text.strip():
        return ""

    def _normalize_nul_escapes(code_text):
        """Normalize embedded NUL bytes to a literal Rust escape sequence."""
        return code_text.replace("\x00", r"\0")

    match = re.search(r'```(?:rust|rs|Rust)\s*\n(.*?)```', response_text, re.DOTALL)
    if match:
        return _normalize_nul_escapes(match.group(1).strip())

    for m in re.finditer(r'```\w*\s*\n(.*?)```', response_text, re.DOTALL):
        code = m.group(1).strip()
        if '#![no_std]' in code or 'aya_ebpf' in code:
            return _normalize_nul_escapes(code)

    stripped = response_text.strip()
    if '#![no_std]' in stripped and ('aya_ebpf' in stripped or 'no_main' in stripped):

        stripped = re.sub(r'^```\w*\n?', '', stripped)
        stripped = re.sub(r'\n?```$', '', stripped)
        return _normalize_nul_escapes(stripped.strip())

    return ""
