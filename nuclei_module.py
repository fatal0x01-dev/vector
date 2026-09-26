"""
Nuclei module
=============
Runs nuclei's template-based vulnerability scanner against discovered
HTTP(S) ports. Uses -jsonl for line-delimited JSON output, one object
per finding.
"""

from __future__ import annotations

import json
from typing import Any

from core.module_base import Module
from core.registry import register_implementation


@register_implementation("nuclei")
class NucleiModule(Module):
    default_fact_type = "finding"
    timeout_seconds = 900

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        return service_fact.get("service", "").lower() in ("http", "https", "http-alt", "https-alt")

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        host = target_ctx["host"]
        port = target_ctx["port"]
        scheme = "https" if "https" in target_ctx.get("service", "") else "http"
        url = f"{scheme}://{host}:{port}"
        return ["nuclei", "-u", url, "-jsonl", "-silent"]

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

            info = record.get("info", {})
            template_id = record.get("template-id") or record.get("template_id")
            severity = info.get("severity", "unknown")

            facts.append({
                "type": "finding",
                "data": {
                    "port": target_ctx["port"],
                    "finding": template_id or info.get("name", "unknown"),
                    "severity": severity,
                    "verified": True,  # nuclei only reports confirmed matches
                    "matched_at": record.get("matched-at") or record.get("matched_at"),
                },
            })
        return facts
