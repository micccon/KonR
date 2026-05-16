"""Vector memory backed by ChromaDB — semantic recall across engagements."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

import anthropic
import chromadb
import chromadb.api

from konr.core import config

COLLECTIONS = frozenset(["tool_outputs", "techniques", "osint_data", "code_artifacts", "knowledge"])
_SUMMARIZE_THRESHOLD = 16_000  # chars; content larger than this is summarized before storing
_SEARCH_DISTANCE_MAX = 0.8     # cosine distance; results beyond this are discarded


class VectorMemory:
    """
    Semantic memory store for a KonR instance.

    One VectorMemory is shared for the lifetime of the process (across engagements).
    Collections are namespaced by content type, not by engagement — use metadata
    filtering to scope queries to a specific engagement.
    """

    def __init__(
        self,
        persist_dir: str | Path = "./work/memory",
        _client: chromadb.api.ClientAPI | None = None,
    ) -> None:
        self._chroma = _client or chromadb.PersistentClient(path=str(persist_dir))
        self._cols = {
            name: self._chroma.get_or_create_collection(
                name,
                metadata={"hnsw:space": "cosine"},
            )
            for name in COLLECTIONS
        }
        self._anthropic = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)

    # ── Storage ───────────────────────────────────────────────────────────────

    def store(
        self,
        collection: str,
        content: str,
        metadata: dict[str, Any],
        doc_id: str | None = None,
    ) -> str:
        """
        Store content in a collection. Returns the doc_id used.

        Pass an explicit doc_id for idempotent upserts (e.g. knowledge seeding).
        Omit it to auto-generate a UUID (e.g. tool output logging).

        Content longer than 16KB is summarised by Haiku before embedding.
        Metadata values are coerced to ChromaDB-compatible scalars.
        """
        col = self._col(collection)

        if len(content) > _SUMMARIZE_THRESHOLD:
            content = self._haiku_summarize(content)

        safe_meta = _sanitize_metadata(metadata)
        used_id = doc_id or str(uuid4())

        col.upsert(
            documents=[content],
            metadatas=[safe_meta] if safe_meta else None,
            ids=[used_id],
        )
        return used_id

    # ── Search ────────────────────────────────────────────────────────────────

    def search(
        self,
        collection: str,
        query: str,
        n_results: int = 3,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Semantic search against a collection.

        Returns a list of {content, metadata, distance} dicts, ordered by
        relevance, excluding results with cosine distance >= 0.8.

        Pass `where` to filter by metadata fields before ranking, e.g.:
            where={"engagement_id": 1}
            where={"agent": {"$in": ["recon", "osint"]}}
        """
        col = self._col(collection)
        total = col.count()
        if total == 0:
            return []

        kwargs: dict[str, Any] = {
            "query_texts": [query],
            "n_results": min(n_results, total),  # ChromaDB raises if n_results > collection size
        }
        if where:
            kwargs["where"] = where

        results = col.query(**kwargs)

        return [
            {"content": doc, "metadata": meta, "distance": dist}
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0],
            )
            if dist < _SEARCH_DISTANCE_MAX
        ]

    def format_results(self, results: list[dict[str, Any]]) -> str:
        """Format search results as a string suitable for inclusion in an agent message."""
        if not results:
            return "No relevant memory found."
        parts = []
        for r in results:
            meta = r["metadata"]
            header = (
                f"[{meta.get('tool', 'unknown')} "
                f"on {meta.get('target', '?')} "
                f"at {meta.get('timestamp', '?')}]"
            )
            parts.append(f"{header}\n{r['content'][:config.MEMORY_RESULT_MAX_CHARS]}")
        return "\n\n---\n\n".join(parts)

    # ── Deletion ──────────────────────────────────────────────────────────────

    def delete_by_engagement(self, collection: str, engagement_id: int) -> int:
        """Delete all documents for an engagement. Returns count deleted."""
        col = self._col(collection)
        results = col.get(where={"engagement_id": engagement_id})
        ids = results["ids"]
        if ids:
            col.delete(ids=ids)
        return len(ids)

    # ── Inspection ────────────────────────────────────────────────────────────

    def count(self, collection: str) -> int:
        return self._col(collection).count()

    def reset_collection(self, collection: str) -> None:
        """Drop and recreate a collection. Used by the knowledge seeder."""
        self._chroma.delete_collection(collection)
        self._cols[collection] = self._chroma.get_or_create_collection(
            collection,
            metadata={"hnsw:space": "cosine"},
        )

    # ── Internals ─────────────────────────────────────────────────────────────

    def _col(self, name: str) -> chromadb.api.models.Collection.Collection:
        if name not in self._cols:
            raise ValueError(
                f"Unknown collection '{name}'. Valid collections: {sorted(COLLECTIONS)}"
            )
        return self._cols[name]

    def _haiku_summarize(self, content: str) -> str:
        try:
            from anthropic.types import TextBlock
            response = self._anthropic.messages.create(
                model=config.HAIKU_MODEL,
                max_tokens=1024,
                messages=[{
                    "role": "user",
                    "content": (
                        "Summarize this security tool output, preserving all findings, "
                        "IP addresses, ports, services, credentials, and vulnerabilities:\n\n"
                        f"{content[:32_000]}"
                    ),
                }],
            )
            for block in response.content:
                if isinstance(block, TextBlock):
                    return block.text
        except Exception:
            pass
        return content[:_SUMMARIZE_THRESHOLD]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sanitize_metadata(metadata: dict[str, Any]) -> dict[str, str | int | float | bool]:
    """Coerce metadata values to ChromaDB-compatible scalars."""
    result: dict[str, str | int | float | bool] = {}
    for k, v in metadata.items():
        if isinstance(v, (bool, int, float, str)):
            result[k] = v
        elif v is None:
            result[k] = ""
        else:
            result[k] = str(v)
    return result
