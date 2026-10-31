"""
provider.py - this talks to the model (Ollama).

OllamaProvider sends chat requests to the local ollama server (default
http://127.0.0.1:11434) and gives back whatever the model replied.

I kept it simple and separate so that if I ever want to test a different
model backend later, I just make a new class with the same generate()
function and nothing else has to change.
"""

from __future__ import annotations

import json
import urllib.request   # built-in library for making http requests
import urllib.error


class ProviderError(RuntimeError):
    # my own error type, raised when ollama can't be reached or breaks
    """Raised when the model backend cannot be reached or returns an error."""


class OllamaProvider:
    """client for a local ollama chat model."""

    def __init__(
        self,
        model: str = "llama3.2",
        base_url: str = "http://127.0.0.1:11434",
        temperature: float = 0.0,   # 0 = most consistent answers (good for testing)
        timeout: int = 120,          # give up after 120s so it can't hang forever
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")   # strip trailing slash just in case
        self.temperature = temperature
        self.timeout = timeout

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """send one system+user message to the model, return its reply text."""

        # build the request body. I send the system prompt and user prompt as
        # separate roles, exactly like a real chatbot - that's what makes the
        # secret-leak test realistic.
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,   # get the whole answer at once, not streamed
            "options": {"temperature": self.temperature},
        }

        # turn the body into JSON and point at ollama's chat endpoint
        data = json.dumps(payload).encode("utf-8")
        url = f"{self.base_url}/api/chat"
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}
        )

        # send it. if ollama isn't running or returns junk, raise a clear error
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise ProviderError(
                f"Could not reach Ollama at {url}. "
                f"Is 'ollama serve' running? Original error: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise ProviderError(f"Ollama returned invalid JSON: {exc}") from exc

        # pull the actual text out of ollama's response
        message = body.get("message", {})
        content = message.get("content", "")
        if not content:
            raise ProviderError(f"Ollama returned an empty response: {body}")
        return content

    def health_check(self) -> bool:
        """quick check that ollama is alive before I start a run."""
        url = f"{self.base_url}/api/tags"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                return resp.status == 200   # 200 = all good
        except urllib.error.URLError:
            return False   # couldn't reach it
