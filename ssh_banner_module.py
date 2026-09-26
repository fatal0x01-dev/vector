"""
SSH banner module
==================
Grabs the SSH banner string, which often leaks OS/version info useful
for later CVE matching. Implemented with a plain socket connection
instead of shelling out to an external binary -- this shows the base
class handles non-subprocess tools too by overriding run().
"""

from __future__ import annotations

import socket
from typing import Any

from core.module_base import Module, ModuleResult
from core.registry import register_implementation


@register_implementation("ssh-banner")
class SSHBannerModule(Module):
    name = "ssh-banner"
    default_fact_type = "finding"
    timeout_seconds = 10

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        return service_fact.get("service", "").lower() == "ssh"

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        # No subprocess involved; documented here for interface consistency.
        return ["<socket>", target_ctx["host"], str(target_ctx["port"])]

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        banner = raw_stdout.strip()
        if not banner:
            return []
        return [{
            "type": "finding",
            "data": {
                "port": target_ctx["port"],
                "banner": banner,
            },
        }]

    def run(self, target_ctx: dict[str, Any]) -> ModuleResult:
        host = target_ctx["host"]
        port = target_ctx["port"]
        log_path = self._log_path(host)
        cmd = self.build_command(target_ctx)

        try:
            with socket.create_connection((host, port), timeout=self.timeout_seconds) as sock:
                banner = sock.recv(1024).decode(errors="replace")

            self._write_log(log_path, cmd, banner, "", 0)
            raw_facts = self.parse_output(banner, target_ctx)
            facts = [self._to_envelope(f, host) for f in raw_facts]

            return ModuleResult(
                module_name=self.name, host=host, success=True,
                facts=facts, log_path=str(log_path),
            )
        except Exception as e:  # noqa: BLE001
            self._write_log(log_path, cmd, "", str(e), -1)
            return ModuleResult(
                module_name=self.name, host=host, success=False,
                log_path=str(log_path), error=str(e),
            )
