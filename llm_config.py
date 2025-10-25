"""
LLM Configuration for dLNk dLNk Framework
Supports: OpenAI, Ollama (Local), LM Studio, LocalAI
"""

import os
from typing import Literal

# LLM Provider Selection
# คุณใช้ Ollama (Local LLM) เท่านั้น - ฟรี 100%
LLM_PROVIDER: Literal["openai", "ollama", "lmstudio", "localai"] = os.getenv("LLM_PROVIDER", "ollama")

# OpenAI Configuration (ไม่ใช้ - เพื่อการพัฒนาแบบฟรี)
# OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
# OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
# OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "")

# Ollama Configuration (Local - ฟรี 100%)
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "localhost")
OLLAMA_PORT = os.getenv("OLLAMA_PORT", "11434")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/v1")
# Available models:
# - mixtral:latest (26GB) - Best for complex tasks
# - llama3:8b-instruct-fp16 (16GB) - High quality instruction following
# - llama3:latest (4.7GB) - Fast and efficient
# - codellama:latest (3.8GB) - Best for code generation
# - mistral:latest (4.4GB) - Good balance
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mixtral:latest")  # เปลี่ยนได้ตามต้องการ
OLLAMA_API_KEY = "ollama"  # Not used but required by OpenAI client
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "600"))  # seconds

# LM Studio Configuration (ไม่ใช้)
# LMSTUDIO_HOST = os.getenv("LMSTUDIO_HOST", "localhost")
# LMSTUDIO_PORT = os.getenv("LMSTUDIO_PORT", "1234")
# LMSTUDIO_BASE_URL = os.getenv("LMSTUDIO_BASE_URL", f"http://{LMSTUDIO_HOST}:{LMSTUDIO_PORT}/v1")
# LMSTUDIO_MODEL = os.getenv("LMSTUDIO_MODEL", "local-model")
# LMSTUDIO_API_KEY = "lm-studio"

# LocalAI Configuration (ไม่ใช้)
# LOCALAI_HOST = os.getenv("LOCALAI_HOST", "localhost")
# LOCALAI_PORT = os.getenv("LOCALAI_PORT", "8080")
# LOCALAI_BASE_URL = os.getenv("LOCALAI_BASE_URL", f"http://{LOCALAI_HOST}:{LOCALAI_PORT}/v1")
# LOCALAI_MODEL = os.getenv("LOCALAI_MODEL", "gpt-3.5-turbo")
# LOCALAI_API_KEY = "local"

# Temperature & Generation Settings
TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.7"))
MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "4000"))
TOP_P = float(os.getenv("LLM_TOP_P", "0.9"))

# Timeout Settings
REQUEST_TIMEOUT = int(os.getenv("LLM_REQUEST_TIMEOUT", "120"))  # seconds

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

