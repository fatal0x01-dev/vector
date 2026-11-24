"""
Generic nmap NSE script probe
==============================
A lot of the entry-point checks this project wants -- is MongoDB/Redis
listening without auth? can we anonymously enumerate an NFS export? is
SNMP answering on "public"? does this mail/DB service hand back a
useful info-leak banner? -- already have a well-tested nmap NSE script
behind them. Rather than hand-rolling a bespoke protocol client for
each one (re-implementing and maintaining Mongo's wire protocol,
Redis's RESP protocol, MS-SQL's TDS protocol, SNMP's ASN.1 encoding,
none of which this project can verify against a live server here),
this module wraps nmap's script engine generically: give it a port and
a list of script names (the module's YAML `nse_scripts:` key, read via
self.config -- see core/module_base.py and core/registry.py for how
that gets populated) and it runs them, parses the XML this project
already knows how to parse (same shape as nmap_module.py), and turns
each script's output into a `finding`.

Used by: modules/redis.yaml, mongodb.yaml, mssql.yaml, rdp.yaml,
vnc.yaml, nfs.yaml, snmp.yaml, smtp.yaml, mail.yaml.

Engineering trade-off, stated plainly: in exchange for not writing N
custom parsers, you get the script's raw text output rather than a
fully structured fact. A keyword scan over that text (see
_infer_severity) flags the highest-signal entry-point language
("anonymous", "without authentication", "VULNERABLE", "open relay",
etc.) so these still surface clearly in report.md, but it's a
heuristic, not a parser -- if a specific script's output needs
structured fields later, that's a targeted follow-up (one dedicated
parser for one script), not a rewrite of this module.

Requires the script names in question to exist in your nmap's script
database -- run `nmap --script-help <name>` once after install to
confirm. If a name doesn't exist, nmap warns to stderr and simply
produces no output for that script; this module doesn't crash on it,
it just gets nothing back for that one.
"""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from core.module_base import Module, ModuleResult
from core.registry import register_implementation

# Crude but effective: any of these phrases showing up in an NSE
# script's free-text output is a strong signal of a no-auth/exploitable
# condition, worth flagging above "info" even without a structured
# field to check against.
HIGH_SIGNAL_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"anonymous",
        r"without authentication",
        r"no authentication",
        r"authentication:\s*disabled",
        r"VULNERABLE",
        r"open relay",
        r"NULL session",
        r"allows login",
        r"login successful",
    ]
]


@register_implementation("nse-probe")
class NseProbeModule(Module):
    name = "nse-probe"
    default_fact_type = "finding"
    timeout_seconds = 180

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        # Gating happens in YAML (triggers: service/port/tunnel/has_version)
        # via the registry; this module runs whatever scripts its YAML
        # def supplies, so it's "applicable" whenever it's dispatched at all.
        return True

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        host, port = target_ctx["host"], target_ctx["port"]
        scripts = ",".join(self.config.get("nse_scripts", []))
        if not scripts:
            # Defensive: a YAML def that registers "nse-probe" without an
            # nse_scripts list would otherwise run bare `--script ""`.
            scripts = "default"
        cmd = ["nmap", "-Pn", "-p", str(port), "--script", scripts, "-oX", "-"]
        script_args = self.config.get("nse_script_args")
        if script_args:
            cmd += ["--script-args", script_args]
        cmd.append(host)
        return cmd

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []
        if not raw_stdout.strip():
            return facts

        try:
            root = ET.fromstring(raw_stdout)
        except ET.ParseError:
            return facts

        for port_el in root.findall(".//port"):
            for script_el in port_el.findall("script"):
                self._script_to_fact(script_el, target_ctx, facts)
        # A handful of scripts attach to <hostscript> instead of a
        # specific <port> (host-scoped checks); cover that shape too.
        for script_el in root.findall(".//hostscript/script"):
            self._script_to_fact(script_el, target_ctx, facts)

        return facts

    @staticmethod
    def _script_to_fact(script_el, target_ctx: dict[str, Any], facts: list[dict[str, Any]]) -> None:
        script_id = script_el.get("id", "unknown-script")
        output = (script_el.get("output") or "").strip()
        if not output:
            return
        facts.append({
            "type": "finding",
            "data": {
                "port": target_ctx.get("port"),
                "finding": f"nse:{script_id}",
                "severity": NseProbeModule._infer_severity(output),
                "verified": True,  # the script actually ran against the live port
                "output": output,
            },
        })

    @staticmethod
    def _infer_severity(output: str) -> str:
        return "high" if any(p.search(output) for p in HIGH_SIGNAL_PATTERNS) else "info"
