"""
Nmap module
===========
This is the initial enumerator: it doesn't trigger off a service fact
(nothing is known yet), the controller runs it first/unconditionally per
target. Its output seeds the knowledge base with `port` facts, which the
registry then uses to dispatch every other module.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from core.module_base import Module
from core.registry import register_implementation


@register_implementation("nmap")
class NmapModule(Module):
    name = "nmap"
    default_fact_type = "port"
    timeout_seconds = 600

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        # Nmap is the seed module -- always applicable, run once per host
        # by the controller before the dispatch loop, not via triggers.
        return True

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        host = target_ctx["host"]
        # -oX - : XML to stdout, easiest to parse reliably
        return ["nmap", "-sV", "-Pn", "-T4", "-oX", "-", host]

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []
        if not raw_stdout.strip():
            return facts

        root = ET.fromstring(raw_stdout)
        for host_el in root.findall("host"):
            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_num = int(port_el.get("portid"))
                protocol = port_el.get("protocol")  # tcp/udp

                service_el = port_el.find("service")
                service_name = service_el.get("name") if service_el is not None else "unknown"
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None

                facts.append({
                    "type": "port",
                    "data": {
                        "port": port_num,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                        "version": version,
                    },
                })

        return facts
