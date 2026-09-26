"""
smbclient module
=================
Attempts an anonymous (null session) share listing via `smbclient -L`.
Useful as a quick corroboration/fallback alongside enum4linux-ng, and
catches cases where anonymous listing is allowed but full enum isn't.
"""

from __future__ import annotations

import re
from typing import Any

from core.module_base import Module
from core.registry import register_implementation

# Typical smbclient -L output line:
#   sharename       Disk      Comment
#   ---------       ----      -------
#   ADMIN$          Disk      Remote Admin
#   C$              Disk      Default share
#   IPC$            IPC       Remote IPC
SHARE_LINE_RE = re.compile(r"^\s*([\w$.\-]+)\s+(Disk|IPC|Printer)\s*(.*)$")


@register_implementation("smbclient")
class SmbclientModule(Module):
    default_fact_type = "share"
    timeout_seconds = 60

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        return service_fact.get("service", "").lower() in ("smb", "microsoft-ds", "netbios-ssn")

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        host = target_ctx["host"]
        return ["smbclient", "-L", f"//{host}/", "-N"]  # -N: no password (anonymous)

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []
        for line in raw_stdout.splitlines():
            match = SHARE_LINE_RE.match(line)
            if not match:
                continue
            share_name, share_type, comment = match.groups()
            facts.append({
                "type": "share",
                "data": {
                    "name": share_name,
                    "type": share_type,
                    "comment": comment.strip() or None,
                },
            })

        if facts:
            facts.append({
                "type": "finding",
                "data": {
                    "finding": "smb_anonymous_listing_allowed",
                    "severity": "medium",
                    "verified": True,
                },
            })

        return facts
