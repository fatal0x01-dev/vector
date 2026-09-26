"""
enum4linux-ng module
=====================
SMB/Windows domain enumeration -- shares, users, OS info, password
policy. enum4linux-ng supports -oY for YAML output, which is much
easier to parse reliably than its human-readable text output.
"""

from __future__ import annotations

from typing import Any

import yaml

from core.module_base import Module
from core.registry import register_implementation


@register_implementation("enum4linux-ng")
class Enum4linuxNgModule(Module):
    default_fact_type = "finding"
    timeout_seconds = 300

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        return service_fact.get("service", "").lower() in ("smb", "microsoft-ds", "netbios-ssn")

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        host = target_ctx["host"]
        # -A: do all simple enumeration; -oY -: YAML to stdout
        return ["enum4linux-ng", "-A", "-oY", "-", host]

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []
        if not raw_stdout.strip():
            return facts

        try:
            parsed = yaml.safe_load(raw_stdout)
        except yaml.YAMLError:
            return facts

        if not isinstance(parsed, dict):
            return facts

        # Shares
        shares_section = parsed.get("Shares", {}) or {}
        for share_name, share_info in shares_section.items():
            if not isinstance(share_info, dict):
                continue
            facts.append({
                "type": "share",
                "data": {
                    "name": share_name,
                    "type": share_info.get("type"),
                    "comment": share_info.get("comment"),
                    "mapping": share_info.get("mapping"),
                },
            })

        # OS info -> finding
        os_info = parsed.get("OS Information", {}) or {}
        if os_info:
            facts.append({
                "type": "finding",
                "data": {
                    "finding": "os_info",
                    "severity": "info",
                    "verified": True,
                    "details": os_info,
                },
            })

        # Users
        users_section = parsed.get("Users", {}) or {}
        for _, user_info in (users_section.items() if isinstance(users_section, dict) else []):
            if isinstance(user_info, dict) and user_info.get("username"):
                facts.append({
                    "type": "finding",
                    "data": {
                        "finding": "smb_user_enumerated",
                        "severity": "low",
                        "verified": True,
                        "username": user_info.get("username"),
                    },
                })

        return facts
