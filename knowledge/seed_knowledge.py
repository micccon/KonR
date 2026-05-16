#!/usr/bin/env python3
"""Seed the KonR knowledge base with curated pentest reference material.

Run from the project root:
    python knowledge/seed_knowledge.py
    # or
    make seed-knowledge

Idempotent — uses stable doc_ids; safe to re-run (entries are upserted).
Entries are loaded from knowledge/knowledge.json — edit that file to add new material.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from konr.storage.memory import VectorMemory  # noqa: E402

_HERE = Path(__file__).parent
_KNOWLEDGE_FILE = _HERE / "knowledge.json"


def main() -> None:
    """Load entries from knowledge.json and upsert all into the knowledge collection."""
    with open(_KNOWLEDGE_FILE) as f:
        entries: list[dict] = json.load(f)

    print(f"Seeding {len(entries)} knowledge entries...")
    mem = VectorMemory()

    for entry in entries:
        mem.store(
            collection="knowledge",
            content=entry["content"],
            metadata=entry["metadata"],
            doc_id=entry["id"],
        )

    total = mem.count("knowledge")
    print(f"Done. knowledge collection now has {total} documents.")


if __name__ == "__main__":
    main()
