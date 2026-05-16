"""Shared utility functions for KonR tool handling."""
from __future__ import annotations

from typing import Any


def extract_text(content: list[Any]) -> str:
    """Extract and join text blocks from an Anthropic message content list."""
    return " ".join(
        block.text for block in content
        if hasattr(block, "type") and block.type == "text"
    ).strip()
