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
MAX_TOOL_CALLS = 35
MAX_TOOL_CALLS_CTF = 25
MAX_TOOL_CALLS_VERIFIER = 8
STUCK_THRESHOLD = 5
MAX_REFINER_CYCLES = 3
OUTPUT_TRUNCATE_BYTES = 2_048
MAX_CONCURRENT_AGENTS: int = int(os.getenv("KONR_MAX_AGENTS", "3"))
MAX_HISTORY_PAIRS: int = int(os.getenv("KONR_MAX_HISTORY", "6"))
MAX_COST_USD: float | None = float(os.getenv("KONR_MAX_COST", "0")) or None  # 0 → no cap

# Pricing ($/token) for claude-sonnet-4-6
SONNET_INPUT_PRICE:  float = 3.00  / 1_000_000
SONNET_OUTPUT_PRICE: float = 15.00 / 1_000_000
CACHE_READ_PRICE:    float = 0.30  / 1_000_000
CACHE_WRITE_PRICE:   float = 3.75  / 1_000_000

# Pricing ($/token) for claude-haiku-4-5
HAIKU_INPUT_PRICE:       float = 0.80 / 1_000_000
HAIKU_OUTPUT_PRICE:      float = 4.00 / 1_000_000
HAIKU_CACHE_READ_PRICE:  float = 0.08 / 1_000_000
HAIKU_CACHE_WRITE_PRICE: float = 1.00 / 1_000_000


def compute_cost_usd(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_read: int = 0,
    cache_write: int = 0,
) -> float:
    """Return cost in USD for a single API response, using per-model pricing."""
    if "haiku" in model:
        return (
            input_tokens  * HAIKU_INPUT_PRICE
            + output_tokens * HAIKU_OUTPUT_PRICE
            + cache_read    * HAIKU_CACHE_READ_PRICE
            + cache_write   * HAIKU_CACHE_WRITE_PRICE
        )
    return (
        input_tokens  * SONNET_INPUT_PRICE
        + output_tokens * SONNET_OUTPUT_PRICE
        + cache_read    * CACHE_READ_PRICE
        + cache_write   * CACHE_WRITE_PRICE
    )

# Memory
MEMORY_RESULT_MAX_CHARS: int = 1500

# Docker
DOCKER_IMAGE = "konr:latest"

