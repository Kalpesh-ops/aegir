import pytest

pytest.importorskip("google.generativeai")

from src.ai_agent.gemini_client import GeminiAgent


def _agent() -> GeminiAgent:
    # Instantiate without touching the model; _generate_signature does not need
    # network or config.
    agent = GeminiAgent.__new__(GeminiAgent)
    return agent


def test_signature_includes_version() -> None:
    agent = _agent()
    ports_a = [{"portid": 21, "service": "ftp", "product": "vsftpd", "version": "2.3.4"}]
    ports_b = [{"portid": 21, "service": "ftp", "product": "vsftpd", "version": "3.0.5"}]
    assert agent._generate_signature(ports_a, []) != agent._generate_signature(ports_b, [])


def test_signature_stable_order() -> None:
    agent = _agent()
    a = [
        {"portid": 80, "service": "http", "product": "nginx", "version": "1.18"},
        {"portid": 22, "service": "ssh", "product": "openssh", "version": "8.4"},
    ]
    b = list(reversed(a))
    assert agent._generate_signature(a, []) == agent._generate_signature(b, [])
