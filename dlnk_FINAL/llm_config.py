"""
LLM Configuration for dLNk dLNk Framework
Supports: OpenAI, Ollama (Local), LM Studio, LocalAI
"""

import os
from typing import Literal

# LLM Provider Selection
LLM_PROVIDER: Literal["openai", "ollama", "lmstudio", "localai"] = "ollama"

# OpenAI Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = "gpt-4.1-mini"  # or gpt-4.1-nano, gemini-2.5-flash
OPENAI_BASE_URL = None  # Use default

# Ollama Configuration (Local)
OLLAMA_BASE_URL = "http://localhost:11434/v1"
OLLAMA_MODEL = "mixtral:latest"  # or llama3.2, mistral, codellama
OLLAMA_API_KEY = "ollama"  # Not used but required by OpenAI client

# LM Studio Configuration (Local)
LMSTUDIO_BASE_URL = "http://localhost:1234/v1"
LMSTUDIO_MODEL = "local-model"  # Model name in LM Studio
LMSTUDIO_API_KEY = "lm-studio"

# LocalAI Configuration (Local)
LOCALAI_BASE_URL = "http://localhost:8080/v1"
LOCALAI_MODEL = "gpt-3.5-turbo"  # Model alias in LocalAI
LOCALAI_API_KEY = "local"

# Temperature & Generation Settings
TEMPERATURE = 0.7
MAX_TOKENS = 4000
TOP_P = 0.9

# Timeout Settings
REQUEST_TIMEOUT = 120  # seconds

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

