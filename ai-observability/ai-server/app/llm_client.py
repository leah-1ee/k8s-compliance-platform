import os
import re
from typing import Literal
from urllib.parse import urlencode

import httpx


LLMProvider = Literal["openai", "anthropic", "google", "xai"]

PROVIDER_DEFAULTS = {
    "openai": {
        "api_url": "https://api.openai.com/v1/chat/completions",
        "model": "gpt-4o-mini",
    },
    "anthropic": {
        "api_url": "https://api.anthropic.com/v1/messages",
        "model": "claude-3-5-haiku-latest",
    },
    "google": {
        "api_url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "model": "gemini-2.0-flash",
    },
    "xai": {
        "api_url": "https://api.x.ai/v1/chat/completions",
        "model": "grok-2-latest",
    },
}


def normalize_provider(value: str | None) -> LLMProvider:
    # 제공자 정규화
    normalized = (value or os.getenv("LLM_PROVIDER", "google")).strip().lower()
    if normalized in {"openai", "anthropic", "google", "xai"}:
        return normalized  # type: ignore[return-value]
    return "google"


class LLMClient:
    def __init__(self, provider: str | None = None, api_key: str | None = None) -> None:
        # LLM 환경 설정
        self.provider = normalize_provider(provider)
        provider_prefix = self.provider.upper()
        defaults = PROVIDER_DEFAULTS[self.provider]
        self.model = (
            os.getenv(f"{provider_prefix}_MODEL")
            or os.getenv("LLM_MODEL")
            or defaults["model"]
        ).strip()
        self.api_url = (
            os.getenv(f"{provider_prefix}_API_URL")
            or os.getenv("LLM_API_URL")
            or defaults["api_url"]
        ).strip()
        self.api_key = (
            (api_key or "").strip()
            or os.getenv(f"{provider_prefix}_API_KEY", "").strip()
            or os.getenv("LLM_API_KEY", "").strip()
        )
        self.timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "12"))

    @property
    def configured(self) -> bool:
        # LLM 설정 여부
        return bool(self.api_url and self.api_key)

    def review_policy(self, prompt: str) -> str:
        # LLM 정책 검토
        if not self.configured:
            return ""

        if self.provider == "anthropic":
            return self._review_policy_anthropic(prompt)
        if self.provider == "google":
            return self._review_policy_google(prompt)
        return self._review_policy_openai_compatible(prompt)

    def _review_policy_openai_compatible(self, prompt: str) -> str:
        # OpenAI 호환 요청
        payload = {
            "model": self.model,
            "messages": self._messages(prompt),
            "max_tokens": 700,
            "temperature": 0,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(self.api_url, headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()

        return self._normalize_review(
            body.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )

    def _review_policy_anthropic(self, prompt: str) -> str:
        # Anthropic 요청
        payload = {
            "model": self.model,
            "max_tokens": 420,
            "system": self._system_prompt(),
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(self.api_url, headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()

        content = body.get("content", [])
        if content and isinstance(content[0], dict):
            return self._normalize_review(content[0].get("text", "").strip())
        return ""

    def _review_policy_google(self, prompt: str) -> str:
        # Google 요청
        api_url = self.api_url.format(model=self.model)
        separator = "&" if "?" in api_url else "?"
        url = f"{api_url}{separator}{urlencode({'key': self.api_key})}"
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": f"{self._system_prompt()}\n\n{prompt}"}],
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 420,
            },
        }
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, headers={"Content-Type": "application/json"}, json=payload)
            response.raise_for_status()
            body = response.json()

        candidates = body.get("candidates", [])
        parts = (
            candidates[0].get("content", {}).get("parts", [])
            if candidates and isinstance(candidates[0], dict)
            else []
        )
        if parts and isinstance(parts[0], dict):
            return self._normalize_review(parts[0].get("text", "").strip())
        return ""

    def _messages(self, prompt: str) -> list[dict[str, str]]:
        # 채팅 메시지
        return [
            {"role": "system", "content": self._system_prompt()},
            {"role": "user", "content": prompt},
        ]

    def _system_prompt(self) -> str:
        # 시스템 프롬프트
        return (
            "You review Kubernetes Gatekeeper policies. "
            "Return only concise Korean plain text. "
            "Do not return Markdown, bullets, code blocks, YAML, or Rego."
        )

    def _normalize_review(self, value: str) -> str:
        # 검토 결과 정리
        cleaned_lines = []
        in_code_block = False
        for raw_line in value.splitlines():
            line = raw_line.strip()
            if line.startswith("```"):
                in_code_block = not in_code_block
                continue
            if in_code_block or not line:
                continue
            line = re.sub(r"^#{1,6}\s*", "", line)
            line = re.sub(r"^[-*•]\s*", "", line)
            line = re.sub(r"^\d+[.)]\s*", "", line)
            line = line.replace("**", "").replace("`", "").replace("*", "")
            cleaned_lines.append(line)
            if len(cleaned_lines) >= 4:
                break
        return "\n".join(cleaned_lines).strip()[:900]
