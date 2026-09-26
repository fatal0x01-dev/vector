"""
FTP anonymous-login check module
==================================
Attempts an anonymous FTP login using the raw protocol over a socket
(no external binary needed, similar approach to the SSH banner module).
Flags a `finding` if anonymous access is permitted -- a common and
high-value misconfiguration to catch early.
"""

from __future__ import annotations

import socket
from typing import Any

from core.module_base import Module, ModuleResult
from core.registry import register_implementation


@register_implementation("ftp-anon-check")
class FtpAnonCheckModule(Module):
    name = "ftp-anon-check"
    default_fact_type = "finding"
    timeout_seconds = 15

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        return service_fact.get("service", "").lower() == "ftp"

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        return ["<socket-ftp>", target_ctx["host"], str(target_ctx["port"])]

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []
        if "230" in raw_stdout:  # 230 = login successful
            facts.append({
                "type": "finding",
                "data": {
                    "port": target_ctx["port"],
                    "finding": "ftp_anonymous_login_allowed",
                    "severity": "high",
                    "verified": True,
                },
            })
            facts.append({
                "type": "credential",
                "data": {
                    "credential": {"username": "anonymous", "password": "anonymous"},
                },
            })
        return facts

    def run(self, target_ctx: dict[str, Any]) -> ModuleResult:
        host = target_ctx["host"]
        port = target_ctx["port"]
        log_path = self._log_path(host)
        cmd = self.build_command(target_ctx)
        transcript = ""

        try:
            with socket.create_connection((host, port), timeout=self.timeout_seconds) as sock:
                sock.settimeout(self.timeout_seconds)
                transcript += sock.recv(1024).decode(errors="replace")

                sock.sendall(b"USER anonymous\r\n")
                transcript += sock.recv(1024).decode(errors="replace")

                sock.sendall(b"PASS anonymous@\r\n")
                transcript += sock.recv(1024).decode(errors="replace")

            self._write_log(log_path, cmd, transcript, "", 0)
            raw_facts = self.parse_output(transcript, target_ctx)
            facts = [self._to_envelope(f, host) for f in raw_facts]

            return ModuleResult(
                module_name=self.name, host=host, success=True,
                facts=facts, log_path=str(log_path),
            )
        except Exception as e:  # noqa: BLE001
            self._write_log(log_path, cmd, transcript, str(e), -1)
            return ModuleResult(
                module_name=self.name, host=host, success=False,
                log_path=str(log_path), error=str(e),
            )
