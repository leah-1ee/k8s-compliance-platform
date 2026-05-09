import os

import httpx


class LLMClient:
    def __init__(self) -> None:
        # LLM 환경 설정
        self.api_url = os.getenv("LLM_API_URL", "").strip()
        self.api_key = os.getenv("LLM_API_KEY", "").strip()
        self.model = os.getenv("LLM_MODEL", "gpt-4o-mini").strip()
        self.timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "12"))

    @property
    def configured(self) -> bool:
        # LLM 설정 여부
        return bool(self.api_url and self.api_key)

    def review_policy(self, prompt: str) -> str:
        # LLM 정책 검토
        if not self.configured:
            return ""

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You review Kubernetes Gatekeeper policies. "
                        "Return concise Korean review notes only."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(self.api_url, headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()

        return (
            body.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )[:2000]
