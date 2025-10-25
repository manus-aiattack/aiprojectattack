"""
LLM Configuration for dLNk Attack Platform
Supports: OpenAI, Ollama (Local), LM Studio, LocalAI
Uses environment variables for all configuration
"""

import os
from typing import Literal, Optional
from config.env_loader import get_env, get_env_int, get_env_float

# LLM Provider Selection
LLM_PROVIDER: Literal["openai", "ollama", "lmstudio", "localai"] = get_env("LLM_PROVIDER", "ollama")

# OpenAI Configuration
OPENAI_API_KEY = get_env("OPENAI_API_KEY", "")
OPENAI_MODEL = get_env("OPENAI_MODEL", "gpt-4.1-mini")
OPENAI_BASE_URL = get_env("OPENAI_BASE_URL") or None  # Use default if not set

# Ollama Configuration (Local - ฟรี 100%)
OLLAMA_HOST = get_env("OLLAMA_HOST", "localhost")
OLLAMA_PORT = get_env_int("OLLAMA_PORT", 11434, min_value=1, max_value=65535)
OLLAMA_BASE_URL = get_env("OLLAMA_BASE_URL", f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/v1")

# Available Ollama models:
# - mixtral:latest (26GB) - Best for complex tasks
# - llama3:8b-instruct-fp16 (16GB) - High quality instruction following
# - llama3:latest (4.7GB) - Fast and efficient
# - codellama:latest (3.8GB) - Best for code generation
# - mistral:latest (4.4GB) - Good balance
OLLAMA_MODEL = get_env("OLLAMA_MODEL", "mixtral:latest")
OLLAMA_API_KEY = get_env("OLLAMA_API_KEY", "ollama")  # Not used but required by OpenAI client

# LM Studio Configuration (Local)
LMSTUDIO_HOST = get_env("LMSTUDIO_HOST", "localhost")
LMSTUDIO_PORT = get_env_int("LMSTUDIO_PORT", 1234, min_value=1, max_value=65535)
LMSTUDIO_BASE_URL = get_env("LMSTUDIO_BASE_URL", f"http://{LMSTUDIO_HOST}:{LMSTUDIO_PORT}/v1")
LMSTUDIO_MODEL = get_env("LMSTUDIO_MODEL", "local-model")  # Model name in LM Studio
LMSTUDIO_API_KEY = get_env("LMSTUDIO_API_KEY", "lm-studio")

# LocalAI Configuration (Local)
LOCALAI_HOST = get_env("LOCALAI_HOST", "localhost")
LOCALAI_PORT = get_env_int("LOCALAI_PORT", 8080, min_value=1, max_value=65535)
LOCALAI_BASE_URL = get_env("LOCALAI_BASE_URL", f"http://{LOCALAI_HOST}:{LOCALAI_PORT}/v1")
LOCALAI_MODEL = get_env("LOCALAI_MODEL", "gpt-3.5-turbo")  # Model alias in LocalAI
LOCALAI_API_KEY = get_env("LOCALAI_API_KEY", "local")

# Temperature & Generation Settings
TEMPERATURE = get_env_float("LLM_TEMPERATURE", 0.7, min_value=0.0, max_value=2.0)
MAX_TOKENS = get_env_int("LLM_MAX_TOKENS", 4000, min_value=1)
TOP_P = get_env_float("LLM_TOP_P", 0.9, min_value=0.0, max_value=1.0)

# Timeout Settings
REQUEST_TIMEOUT = get_env_int("LLM_REQUEST_TIMEOUT", 120, min_value=1)


def get_llm_config():
    """Get LLM configuration based on selected provider"""
    
    if LLM_PROVIDER == "openai":
        return {
            "base_url": OPENAI_BASE_URL,
            "api_key": OPENAI_API_KEY,
            "model": OPENAI_MODEL,
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
            "timeout": REQUEST_TIMEOUT
        }
    
    elif LLM_PROVIDER == "ollama":
        return {
            "base_url": OLLAMA_BASE_URL,
            "api_key": OLLAMA_API_KEY,
            "model": OLLAMA_MODEL,
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
            "timeout": REQUEST_TIMEOUT
        }
    
    elif LLM_PROVIDER == "lmstudio":
        return {
            "base_url": LMSTUDIO_BASE_URL,
            "api_key": LMSTUDIO_API_KEY,
            "model": LMSTUDIO_MODEL,
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
            "timeout": REQUEST_TIMEOUT
        }
    
    elif LLM_PROVIDER == "localai":
        return {
            "base_url": LOCALAI_BASE_URL,
            "api_key": LOCALAI_API_KEY,
            "model": LOCALAI_MODEL,
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
            "timeout": REQUEST_TIMEOUT
        }
    
    else:
        raise ValueError(f"Unknown LLM provider: {LLM_PROVIDER}")


def print_config():
    """Print current LLM configuration"""
    config = get_llm_config()
    print(f"🤖 LLM Provider: {LLM_PROVIDER.upper()}")
    print(f"📡 Base URL: {config['base_url']}")
    print(f"🎯 Model: {config['model']}")
    print(f"🌡️  Temperature: {config['temperature']}")
    print(f"📊 Max Tokens: {config['max_tokens']}")
    print(f"⏱️  Timeout: {config['timeout']}s")


if __name__ == "__main__":
    print_config()

