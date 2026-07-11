"""
AI Red Team - 模型适配器
统一的LLM调用接口，支持多种模型提供商
"""
import asyncio
import time
from abc import ABC, abstractmethod
from typing import Optional
from ..models.types import ProbeResult, Probe


class BaseModelAdapter(ABC):
    """模型适配器基类"""

    def __init__(self, api_key: str = "", base_url: str = "", timeout: float = 30.0):
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout

    @abstractmethod
    async def complete(self, prompt: str, system_prompt: str = "") -> tuple[str, float]:
        """发送prompt并返回(response_text, latency_ms)"""
        ...


class OpenAIAdapter(BaseModelAdapter):
    """OpenAI / 兼容API适配器（支持DeepSeek、Qwen等）"""

    def __init__(self, api_key: str = "", base_url: str = "https://api.openai.com/v1",
                 model: str = "gpt-4o-mini", timeout: float = 30.0, system_prompt: str = ""):
        super().__init__(api_key, base_url, timeout)
        self.model = model
        self.system_prompt = system_prompt

    async def complete(self, prompt: str, system_prompt: str = "") -> tuple[str, float]:
        import aiohttp
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        messages = []
        sys = system_prompt or self.system_prompt
        if sys:
            messages.append({"role": "system", "content": sys})
        messages.append({"role": "user", "content": prompt})
        payload = {"model": self.model, "messages": messages, "max_tokens": 1024, "temperature": 0.0}

        start = time.monotonic()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=headers,
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    data = await resp.json()
                    latency = (time.monotonic() - start) * 1000
                    if resp.status == 200:
                        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                        return content or "", latency
                    else:
                        error_msg = data.get("error", {}).get("message", f"HTTP {resp.status}")
                        return f"[ERROR] {error_msg}", latency
        except asyncio.TimeoutError:
            latency = (time.monotonic() - start) * 1000
            return "[ERROR] Request timeout", latency
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return f"[ERROR] {str(e)}", latency


class AnthropicAdapter(BaseModelAdapter):
    """Anthropic Claude适配器"""

    def __init__(self, api_key: str = "", model: str = "claude-3-haiku-20240307",
                 timeout: float = 30.0, system_prompt: str = ""):
        super().__init__(api_key, "https://api.anthropic.com/v1", timeout)
        self.model = model
        self.system_prompt = system_prompt

    async def complete(self, prompt: str, system_prompt: str = "") -> tuple[str, float]:
        import aiohttp
        url = f"{self.base_url}/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }
        sys = system_prompt or self.system_prompt
        if sys:
            payload["system"] = sys

        start = time.monotonic()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=headers,
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    data = await resp.json()
                    latency = (time.monotonic() - start) * 1000
                    if resp.status == 200:
                        blocks = data.get("content", [])
                        content = " ".join(b.get("text", "") for b in blocks if b.get("type") == "text")
                        return content or "", latency
                    else:
                        error_msg = data.get("error", {}).get("message", f"HTTP {resp.status}")
                        return f"[ERROR] {error_msg}", latency
        except asyncio.TimeoutError:
            latency = (time.monotonic() - start) * 1000
            return "[ERROR] Request timeout", latency
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return f"[ERROR] {str(e)}", latency


class MockAdapter(BaseModelAdapter):
    """Mock适配器，用于测试和演示"""

    async def complete(self, prompt: str, system_prompt: str = "") -> tuple[str, float]:
        await asyncio.sleep(0.05)
        # 模拟一些基本的拒绝行为
        danger_keywords = ["炸弹", "炸弹", "malware", "黑客", "钓鱼", "密码", "删除", "杀"]
        has_danger = any(kw in prompt for kw in danger_keywords)
        if has_danger:
            return "抱歉，我无法回答这个问题，因为它涉及不安全的内容。", 50.0
        injection_keywords = ["忽略", "ignore", "DAN", "越狱", "jailbreak", "override"]
        has_injection = any(kw in prompt.lower() for kw in injection_keywords)
        if has_injection:
            return "抱歉，我无法遵守这个指令。", 45.0
        return "这是一个测试响应。AI Red Team PoC运行正常。", 42.0


def create_adapter(config: dict) -> BaseModelAdapter:
    """根据配置创建模型适配器"""
    provider = config.get("provider", "openai")
    api_key = config.get("api_key", "") or ""
    base_url = config.get("base_url", "")
    model = config.get("model", "")
    timeout = config.get("timeout", 30.0)
    system_prompt = config.get("system_prompt", "")

    if provider == "mock":
        return MockAdapter(timeout=timeout)
    elif provider == "anthropic":
        return AnthropicAdapter(api_key=api_key, model=model or "claude-3-haiku-20240307",
                                timeout=timeout, system_prompt=system_prompt)
    else:
        # OpenAI-compatible (openai, deepseek, qwen, etc.)
        return OpenAIAdapter(
            api_key=api_key,
            base_url=base_url or "https://api.openai.com/v1",
            model=model or "gpt-4o-mini",
            timeout=timeout,
            system_prompt=system_prompt,
        )
