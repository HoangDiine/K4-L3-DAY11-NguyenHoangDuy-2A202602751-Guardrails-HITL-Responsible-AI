"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, tuple[int, float]] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store the request and return its correlation id."""
        request_id = request_id or uuid.uuid4().hex
        started_at = utc_now_iso()
        entry = {
            "request_id": request_id,
            "user_id": user_id,
            "input": text,
            "started_at": started_at,
            "output": None,
            "blocked": False,
            "layer": None,
            "latency_ms": None,
        }
        self.logs.append(entry)
        self._open[request_id] = (len(self.logs) - 1, time.perf_counter())
        return request_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete the correlated request record with its decision and output."""
        now = time.perf_counter()
        if request_id and request_id in self._open:
            index, started = self._open.pop(request_id)
            entry = self.logs[index]
            entry.update(
                {
                    "output": text,
                    "blocked": bool(blocked),
                    "layer": layer,
                    "latency_ms": round((now - started) * 1000, 3),
                    "completed_at": utc_now_iso(),
                }
            )
            return

        self.logs.append(
            {
                "request_id": request_id or uuid.uuid4().hex,
                "user_id": user_id,
                "input": None,
                "started_at": None,
                "output": text,
                "blocked": bool(blocked),
                "layer": layer,
                "latency_ms": None,
                "completed_at": utc_now_iso(),
            }
        )

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
