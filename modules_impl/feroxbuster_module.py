"""
Feroxbuster module
===================
Directory/content brute forcing against discovered HTTP(S) ports.
Uses --json for structured, line-delimited JSON output.
"""

from __future__ import annotations

import json
from typing import Any

from core.module_base import Module
from core.registry import register_implementation

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"


@register_implementation("feroxbuster")
class FeroxbusterModule(Module):
    default_fact_type = "directory"
    timeout_seconds = 600

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        return service_fact.get("service", "").lower() in ("http", "https", "http-alt", "https-alt")

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        host = target_ctx["host"]
        port = target_ctx["port"]
        scheme = "https" if "https" in target_ctx.get("service", "") else "http"
        url = f"{scheme}://{host}:{port}"
        return [
            "feroxbuster",
            "--url", url,
            "--wordlist", DEFAULT_WORDLIST,
            "--json",
            "--quiet",
            "--no-state",
        ]

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            # feroxbuster emits several message "type"s; we only care about
            # the per-URL response results
            if record.get("type") != "response":
                continue

            status = record.get("status")
            url = record.get("url")
            if status is None or url is None:
                continue

            facts.append({
                "type": "directory",
                "data": {
                    "port": target_ctx["port"],
                    "path": url,
                    "status": status,
                    "content_length": record.get("content_length"),
                },
            })
        return facts
