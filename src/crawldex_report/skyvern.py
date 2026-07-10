"""Skyvern adapter helpers for CrawlDex reporting."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Mapping, Optional, Sequence

from .core import CrawlDexReporter, SubmissionReceipt


async def report_skyvern_task(
    *,
    reporter: CrawlDexReporter,
    task_run: Any,
    site: str,
    task: str,
    agent_profile: Optional[Mapping[str, Any]] = None,
    outcome: str,
    friction: Optional[Sequence[str]] = None,
    evidence_signals: Optional[Sequence[str]] = None,
    source_tier: Optional[str] = None,
    occurred_at: Optional[str] = None,
) -> SubmissionReceipt:
    """Submit a redacted Skyvern task summary.

    `task_run` is intentionally not inspected by default. Uploaded document
    names, extracted form values, screenshots, and browser storage stay local.
    """

    started_at = time.monotonic()
    payload = {
        "site": site,
        "task": task,
        "agent_profile": {"stack": "skyvern", **dict(agent_profile or {})},
        "outcome": outcome,
        "friction": list(friction or []),
        "duration_sec": max(0, round(time.monotonic() - started_at)),
        "evidence": {
            "artifact": {
                "schema": "crawldex.evidence.redacted.v1",
                "redaction_status": "hash_only",
                "signals": list(evidence_signals or []),
                "removed_fields": [
                    "uploaded_document_names",
                    "extracted_form_values",
                    "screenshots",
                    "cookies",
                    "storage_state",
                    "network_bodies",
                ],
            },
            "artifact_types": ["action_summary"],
            "redaction_status": "hash_only",
        },
    }
    if source_tier is not None:
        payload["source_tier"] = source_tier
    if occurred_at is not None:
        payload["occurred_at"] = occurred_at

    return await asyncio.to_thread(reporter.report, payload)
