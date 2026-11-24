"""
Module base class
==================
Every tool wrapper (nmap, whatweb, nuclei, enum4linux-ng, ...) subclasses
`Module` and implements three methods:

    applicable(service_fact)  -> bool
    build_command(target_ctx) -> list[str]
    parse_output(raw_stdout)  -> list[dict]   # facts, WITHOUT type/host/source_tool

`run()` is shared: it executes the command as a subprocess, captures
stdout/stderr to a log file, enforces a timeout, and wraps parsed
results into full fact envelopes (adding type default, host, source_tool,
timestamp) before handing them back to the controller.

Concrete modules are lightweight: they only care about how to invoke
their tool and how to turn its output into structured facts.
"""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class ModuleResult:
    """Outcome of running a module against a target."""
    module_name: str
    host: str
    success: bool
    facts: list[dict[str, Any]] = field(default_factory=list)
    log_path: Optional[str] = None
    error: Optional[str] = None


class Module(ABC):
    """
    Abstract base for a tool wrapper.

    Class-level attributes `name`, `triggers`, `produces`, `config` are
    normally populated from the module's YAML definition by the registry,
    but can also be set directly by subclasses for standalone use/testing.

    `config` carries the module's *entire* parsed YAML dict (not just
    triggers/tools/produces), so a module can read arbitrary custom keys
    its YAML def adds -- e.g. `nse_scripts: [...]` for the generic
    nse-probe module (modules_impl/nse_probe_module.py). Modules that
    don't need custom keys can ignore it entirely.
    """

    name: str = "unnamed_module"
    triggers: dict[str, Any] = {}
    produces: list[str] = []
    config: dict[str, Any] = {}
    default_fact_type: str = "finding"
    timeout_seconds: int = 300

    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Must be implemented by concrete modules
    # ------------------------------------------------------------------

    @abstractmethod
    def applicable(self, service_fact: dict[str, Any]) -> bool:
        """
        Given a single service/port fact (e.g. {"port": 80, "service": "http"}),
        return True if this module should run for that fact.
        Typically implemented via self.triggers, but left abstract so
        modules can add custom logic (e.g. version checks).
        """
        raise NotImplementedError

    @abstractmethod
    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        """
        Build the subprocess argv list to execute this tool.
        `target_ctx` includes at minimum {"host": ..., "port": ..., "service": ...}
        plus any other facts the controller chooses to pass in.
        """
        raise NotImplementedError

    @abstractmethod
    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parse raw tool stdout into a list of partial fact dicts, e.g.:
            [{"type": "technology", "data": {"technology": ["Apache", "PHP"]}}]
        `type` is optional per-item; falls back to self.default_fact_type.
        Only `data` (and optionally `type`) need to be set here — host,
        source_tool, and timestamp are filled in by run().
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Shared execution logic
    # ------------------------------------------------------------------

    def run(self, target_ctx: dict[str, Any]) -> ModuleResult:
        host = target_ctx["host"]
        cmd = self.build_command(target_ctx)
        log_path = self._log_path(host)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            self._write_log(log_path, cmd, proc.stdout, proc.stderr, proc.returncode)

            raw_facts = self.parse_output(proc.stdout, target_ctx)
            facts = [self._to_envelope(f, host) for f in raw_facts]

            return ModuleResult(
                module_name=self.name,
                host=host,
                success=True,
                facts=facts,
                log_path=str(log_path),
            )

        except subprocess.TimeoutExpired as e:
            self._write_log(log_path, cmd, e.stdout or "", e.stderr or "", -1, note="TIMEOUT")
            return ModuleResult(
                module_name=self.name, host=host, success=False,
                log_path=str(log_path), error=f"timeout after {self.timeout_seconds}s",
            )
        except FileNotFoundError as e:
            return ModuleResult(
                module_name=self.name, host=host, success=False,
                error=f"tool binary not found: {e}",
            )
        except Exception as e:  # noqa: BLE001 - want to capture any tool failure
            return ModuleResult(
                module_name=self.name, host=host, success=False, error=str(e),
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _to_envelope(self, partial: dict[str, Any], host: str) -> dict[str, Any]:
        return {
            "type": partial.get("type", self.default_fact_type),
            "host": host,
            "source_tool": self.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": partial["data"],
        }

    def _log_path(self, host: str) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_host = host.replace(":", "_").replace("/", "_")
        return self.output_dir / safe_host / f"{self.name}_{ts}.log"

    @staticmethod
    def _write_log(
        path: Path, cmd: list[str], stdout: str, stderr: str, returncode: int,
        note: str = "",
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(f"$ {' '.join(cmd)}\n")
            if note:
                f.write(f"[{note}]\n")
            f.write(f"[exit code: {returncode}]\n\n")
            f.write("--- stdout ---\n")
            f.write(stdout or "(empty)")
            f.write("\n\n--- stderr ---\n")
            f.write(stderr or "(empty)")
