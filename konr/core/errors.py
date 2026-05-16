"""Shared exception types for KonR agents."""
from __future__ import annotations


class ApprovalDeniedError(Exception):
    """Raised when the user skips or stops an approval request."""
    def __init__(self, decision: str) -> None:
        self.decision = decision
        super().__init__(f"Approval {decision}")
