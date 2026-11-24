"""
Nmap module
===========
Seed module: the controller runs this first/unconditionally per target
(nothing is known about the host yet, so it isn't dispatched via
triggers the way every other module is).

Two scans feed the same knowledge base:

  1. A TCP connect+version scan (-sV -Pn), as before.
  2. A fast UDP top-ports sweep (-sU --top-ports 20), new. A meaningful
     share of classic "entry point" misconfigurations live on UDP and
     were invisible to this project before -- SNMP with a default
     community string, an exposed NTP/TFTP responder, an open DNS
     resolver, an unauthenticated RPC portmapper. --top-ports (not a
     full UDP sweep) trades completeness for a scan that actually
     finishes: UDP scanning is inherently slow since there's no
     three-way handshake to confirm closed vs. filtered. Widen the
     port list below if your engagement's scope and time budget allow.

     UDP scanning needs raw-socket privileges (root, or cap_net_raw).
     Without them nmap exits non-zero for that sub-scan; this module
     treats that as a partial failure, not a fatal one -- you still get
     full TCP results.

Both scans produce `port` facts in the same shape, differentiated by
`protocol` ("tcp"/"udp"). Facts now also carry:

  - `state`: "open" or "open|filtered" -- nmap reports the latter for
    UDP ports that didn't respond to the probe, which is ambiguous
    (could be open-and-silent, could be filtered) rather than confirmed
    open the way a TCP SYN/ACK is. Downstream modules and report.py
    both surface this so "open|filtered" results get the appropriately
    lower confidence they deserve.
  - `tunnel`: "ssl" when nmap -sV detected a TLS wrapper around the
    service, else None. This is what lets modules/tls.yaml dispatch the
    TLS audit module (modules_impl/tls_audit_module.py) at ANY
    TLS-wrapped port -- not just 443/8443 -- since nmap already knows a
    port is SSL-wrapped even when the service behind it isn't HTTP
    (ssl/smtp, ssl/imap, a TLS-wrapped custom app port, ...).
  - `extrainfo`: whatever free-text nmap -sV additionally reports
    (e.g. "protocol 2.0" for SSH, a build string, an OS guess) --
    carried through for the report; not currently used by any trigger.
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from core.module_base import Module, ModuleResult
from core.registry import register_implementation

# Common UDP entry points worth the extra scan time: DNS, NTP, SNMP
# (x2 -- community-string brute targets usually probe both), TFTP,
# NetBIOS name service, IKE, RPC portmapper, and a few others nmap's
# own --top-ports ordering would include anyway.
UDP_TOP_PORTS = "20"


@register_implementation("nmap")
class NmapModule(Module):
    name = "nmap"
    default_fact_type = "port"
    timeout_seconds = 900  # covers both the TCP and UDP sub-scans below

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        # Nmap is the seed module -- always applicable, run once per host
        # by the controller before the dispatch loop, not via triggers.
        return True

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        # Documented here for interface consistency / standalone use;
        # run() below issues this PLUS the UDP sweep and merges results.
        return ["nmap", "-sV", "-Pn", "-T4", "-oX", "-", target_ctx["host"]]

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        return self._parse_nmap_xml(raw_stdout)

    @staticmethod
    def _parse_nmap_xml(raw_stdout: str) -> list[dict[str, Any]]:
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
                state = state_el.get("state") if state_el is not None else None
                if state not in ("open", "open|filtered"):
                    continue

                port_num = int(port_el.get("portid"))
                protocol = port_el.get("protocol")  # tcp/udp

                service_el = port_el.find("service")
                service_name = service_el.get("name") if service_el is not None else "unknown"
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None
                tunnel = service_el.get("tunnel") if service_el is not None else None
                extrainfo = service_el.get("extrainfo") if service_el is not None else None

                facts.append({
                    "type": "port",
                    "data": {
                        "port": port_num,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "tunnel": tunnel,
                        "extrainfo": extrainfo,
                        "state": state,
                    },
                })

        return facts

    def run(self, target_ctx: dict[str, Any]) -> ModuleResult:
        host = target_ctx["host"]
        log_path = self._log_path(host)
        all_facts: list[dict[str, Any]] = []
        log_sections: list[str] = []
        errors: list[str] = []

        tcp_cmd = self.build_command(target_ctx)
        try:
            proc = subprocess.run(tcp_cmd, capture_output=True, text=True, timeout=self.timeout_seconds)
            log_sections.append(
                f"$ {' '.join(tcp_cmd)}\n[exit code: {proc.returncode}]\n"
                f"--- stdout ---\n{proc.stdout or '(empty)'}\n--- stderr ---\n{proc.stderr or '(empty)'}"
            )
            all_facts.extend(self._parse_nmap_xml(proc.stdout))
        except FileNotFoundError as e:
            errors.append(f"TCP scan failed: nmap not found ({e})")
            log_sections.append(f"$ {' '.join(tcp_cmd)}\n[ERROR: nmap not found]")
        except subprocess.TimeoutExpired:
            errors.append(f"TCP scan timed out after {self.timeout_seconds}s")
            log_sections.append(f"$ {' '.join(tcp_cmd)}\n[TIMEOUT]")
        except Exception as e:  # noqa: BLE001
            errors.append(f"TCP scan failed: {e}")
            log_sections.append(f"$ {' '.join(tcp_cmd)}\n[ERROR: {e}]")

        udp_cmd = ["nmap", "-sU", "-sV", "-Pn", "-T4", "--top-ports", UDP_TOP_PORTS, "-oX", "-", host]
        try:
            proc = subprocess.run(udp_cmd, capture_output=True, text=True, timeout=self.timeout_seconds)
            log_sections.append(
                f"$ {' '.join(udp_cmd)}\n[exit code: {proc.returncode}]\n"
                f"--- stdout ---\n{proc.stdout or '(empty)'}\n--- stderr ---\n{proc.stderr or '(empty)'}"
            )
            all_facts.extend(self._parse_nmap_xml(proc.stdout))
        except FileNotFoundError as e:
            errors.append(f"UDP scan failed: nmap not found ({e})")
            log_sections.append(f"$ {' '.join(udp_cmd)}\n[ERROR: nmap not found]")
        except subprocess.TimeoutExpired:
            errors.append(f"UDP scan timed out after {self.timeout_seconds}s")
            log_sections.append(f"$ {' '.join(udp_cmd)}\n[TIMEOUT]")
        except Exception as e:  # noqa: BLE001
            # Very commonly "requires root privileges" -- not fatal to
            # the overall run, so logged but not raised.
            errors.append(f"UDP scan failed: {e}")
            log_sections.append(f"$ {' '.join(udp_cmd)}\n[ERROR: {e}]")

        self._write_log(log_path, ["nmap", "(tcp + udp, see sections below)"], "\n\n".join(log_sections), "", 0)

        # Only fail outright if BOTH sub-scans errored AND produced
        # nothing -- a UDP scan failing for lack of root privileges
        # shouldn't take down TCP discovery, which is the far more
        # commonly usable result.
        success = len(errors) < 2 or bool(all_facts)
        return ModuleResult(
            module_name=self.name, host=host, success=success,
            facts=[self._to_envelope(f, host) for f in all_facts],
            log_path=str(log_path),
            error="; ".join(errors) if errors else None,
        )
