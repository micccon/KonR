import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Paths
WORK_DIR = Path("./work")
VPN_DIR = Path("./vpn")

# Models
SONNET_MODEL = "claude-sonnet-4-6"
HAIKU_MODEL = "claude-haiku-4-5-20251001"

# Anthropic
ANTHROPIC_API_KEY: str = os.environ.get("ANTHROPIC_API_KEY", "")

# OSINT API keys (all optional)
SHODAN_API_KEY: str = os.environ.get("SHODAN_API_KEY", "")
CENSYS_API_ID: str = os.environ.get("CENSYS_API_ID", "")
CENSYS_API_SECRET: str = os.environ.get("CENSYS_API_SECRET", "")
HUNTER_API_KEY: str = os.environ.get("HUNTER_API_KEY", "")
VIRUSTOTAL_API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", "")

# Agent limits
MAX_TOOL_CALLS = 50
MAX_TOOL_CALLS_CTF = 25
STUCK_THRESHOLD = 5
MAX_REFINER_CYCLES = 3
OUTPUT_TRUNCATE_BYTES = 8_192
MAX_CONCURRENT_AGENTS: int = int(os.getenv("KONR_MAX_AGENTS", "3"))
MAX_HISTORY_PAIRS: int = int(os.getenv("KONR_MAX_HISTORY", "20"))
MAX_COST_USD: float | None = float(os.getenv("KONR_MAX_COST", "0")) or None

# Pricing ($/token) for claude-sonnet-4-6
SONNET_INPUT_PRICE:  float = 3.00  / 1_000_000
SONNET_OUTPUT_PRICE: float = 15.00 / 1_000_000
CACHE_READ_PRICE:    float = 0.30  / 1_000_000
CACHE_WRITE_PRICE:   float = 3.75  / 1_000_000

# Memory
MEMORY_RESULT_MAX_CHARS: int = 1500

# Docker
DOCKER_IMAGE = "konr:latest"

