"""
WhatWeb module
==============
Fingerprints web technology stack on discovered HTTP(S) ports.
Runs with --log-json for structured, parseable output.
"""

from __future__ import annotations

import json
from typing import Any

from core.module_base import Module
from core.registry import register_implementation


@register_implementation("whatweb")
class WhatWebModule(Module):
    default_fact_type = "technology"
    timeout_seconds = 120

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        return service_fact.get("service", "").lower() in ("http", "https", "http-alt", "https-alt")

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        host = target_ctx["host"]
        port = target_ctx["port"]
        scheme = "https" if "https" in target_ctx.get("service", "") else "http"
        url = f"{scheme}://{host}:{port}"
        return ["whatweb", "--log-json=-", "--no-errors", url]

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

            plugins = record.get("plugins", {})
            technologies = sorted(plugins.keys())
            if not technologies:
                continue

            facts.append({
                "type": "technology",
                "data": {
                    "port": target_ctx["port"],
                    "technology": technologies,
                },
            })
        return facts
