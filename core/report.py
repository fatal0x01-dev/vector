"""
Report generator
=================
Turns a KnowledgeBase's facts into two artifacts per target:

    output/<host>/report.json   -- full raw fact dump, machine-readable
    output/<host>/report.md     -- human-readable summary grouped by
                                    service/port, with technologies,
                                    findings, credentials, directories
                                    called out separately

Designed to be called once per target after its recon run completes,
but works fine on a partially-completed KB too (e.g. inspecting
progress mid-run or after a crash).
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from core.knowledge_base import KnowledgeBase
from core.scorer import score_host


class ReportGenerator:
    def __init__(self, kb: KnowledgeBase, host: str, output_dir: str | Path):
        self.kb = kb
        self.host = host
        self.output_dir = Path(output_dir)

    def generate(self) -> tuple[Path, Path]:
        """Write report.json and report.md, return their paths."""
        json_path = self._write_json()
        md_path = self._write_markdown()
        return json_path, md_path

    # ------------------------------------------------------------------
    # JSON report -- straightforward full dump
    # ------------------------------------------------------------------

    def _write_json(self) -> Path:
        facts = self.kb.get_facts(host=self.host)
        module_status = self.kb.module_status(self.host)

        payload = {
            "host": self.host,
            "entry_point_assessment": score_host(facts),
            "facts": facts,
            "modules_run": module_status,
        }

        path = self.output_dir / "report.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(payload, f, indent=2, default=str)
        return path

    # ------------------------------------------------------------------
    # Markdown report -- grouped, human-readable
    # ------------------------------------------------------------------

    def _write_markdown(self) -> Path:
        facts = self.kb.get_facts(host=self.host)

        ports = [f for f in facts if f["type"] == "port"]
        technologies = [f for f in facts if f["type"] == "technology"]
        webservers = [f for f in facts if f["type"] == "webserver"]
        findings = [f for f in facts if f["type"] == "finding"]
        credentials = [f for f in facts if f["type"] == "credential"]
        directories = [f for f in facts if f["type"] == "directory"]
        shares = [f for f in facts if f["type"] == "share"]

        # Index everything by port so we can render a "per-service" section
        by_port: dict[Any, dict[str, list]] = defaultdict(
            lambda: {"technology": [], "webserver": [], "finding": [], "directory": [], "share": []}
        )
        for f in technologies:
            by_port[f["data"].get("port")]["technology"].append(f)
        for f in webservers:
            by_port[f["data"].get("port")]["webserver"].append(f)
        for f in findings:
            by_port[f["data"].get("port")]["finding"].append(f)
        for f in directories:
            by_port[f["data"].get("port")]["directory"].append(f)
        for f in shares:
            by_port[f["data"].get("port")]["share"].append(f)

        lines: list[str] = []
        lines.append(f"# Recon Report: {self.host}")
        lines.append("")
        lines.append(f"**Open ports discovered:** {len(ports)}")
        lines.append(f"**Findings:** {len(findings)}  |  **Credentials:** {len(credentials)}")
        lines.append("")

        # --- Entry-point assessment (lead section -- see core/scorer.py) ---
        assessment = score_host(facts)
        lines.append("## Entry-Point Assessment")
        lines.append("")
        lines.append(f"**Score:** {assessment['score']}  |  **Tier:** `{assessment['tier']}`")
        lines.append("")
        bd = assessment["breakdown"]
        lines.append(
            f"Breakdown — credentials: {bd['credentials']}, critical: {bd['critical']}, "
            f"high: {bd['high']}, medium: {bd['medium']}, low: {bd['low']}"
        )
        lines.append("")
        if assessment["entry_points"]:
            lines.append("Ranked by contribution to the score (highest first):")
            lines.append("")
            lines.append("| Points | Severity | Port | Entry point | Source |")
            lines.append("|--------|----------|------|--------------|--------|")
            for ep in assessment["entry_points"]:
                lines.append(
                    f"| {ep['points']} | {ep['severity']} | {ep['port'] if ep['port'] is not None else ''} "
                    f"| {ep['label']} | {ep['source_tool']} |"
                )
        else:
            lines.append(
                "_No scored entry points. This means nothing this pipeline's modules flagged -- "
                "not that the host has no weaknesses; see core/scorer.py for what is and isn't counted._"
            )
        lines.append("")

        # --- Ports / services table ---
        lines.append("## Open Ports")
        lines.append("")
        if ports:
            lines.append("| Port | Protocol | Service | Product | Version | State |")
            lines.append("|------|----------|---------|---------|---------|-------|")
            for f in sorted(ports, key=lambda x: x["data"].get("port", 0)):
                d = f["data"]
                # "open|filtered" (UDP ports that didn't respond to the
                # probe) is lower-confidence than a confirmed "open" TCP
                # port -- surfaced here rather than silently treated the
                # same way. See nmap_module.py docstring.
                lines.append(
                    f"| {d.get('port')} | {d.get('protocol', '')} | {d.get('service', '')} "
                    f"| {d.get('product') or ''} | {d.get('version') or ''} | {d.get('state') or ''} |"
                )
        else:
            lines.append("_No open ports recorded._")
        lines.append("")

        # --- Per-port detail ---
        lines.append("## Service Detail")
        lines.append("")
        for port_fact in sorted(ports, key=lambda x: x["data"].get("port", 0)):
            port = port_fact["data"].get("port")
            service = port_fact["data"].get("service")
            lines.append(f"### Port {port} ({service})")

            detail = by_port.get(port, {})

            if detail.get("webserver"):
                for f in detail["webserver"]:
                    d = f["data"]
                    parts = [p for p in (d.get("server"), d.get("x_powered_by")) if p]
                    if parts:
                        lines.append(f"- **Web server:** {' / '.join(parts)}")

            if detail.get("technology"):
                techs = sorted({t for f in detail["technology"] for t in f["data"].get("technology", [])})
                lines.append(f"- **Technologies:** {', '.join(techs)}")

            if detail.get("directory"):
                dirs = sorted({f["data"].get("path", "") for f in detail["directory"]})
                lines.append(f"- **Directories found:** {', '.join(d for d in dirs if d)}")

            if detail.get("share"):
                share_names = sorted({f["data"].get("name", "") for f in detail["share"]})
                lines.append(f"- **Shares:** {', '.join(s for s in share_names if s)}")

            if detail.get("finding"):
                lines.append("- **Findings:**")
                for f in detail["finding"]:
                    d = f["data"]
                    if "cve" in d or "finding" in d:
                        label = d.get("finding") or d.get("cve")
                        cve = d.get("cve")
                        # exploitdb/NVD facts set both "finding" (a generic
                        # label like "exploitdb_match") and "cve" -- show the
                        # actual CVE id too rather than just the generic label.
                        cve_txt = f" [{cve}]" if cve and cve != label else ""
                        sev = d.get("severity", "")
                        verified = d.get("verified")
                        vtxt = " (verified)" if verified else ""
                        # A few finding types carry extra structured fields
                        # (modules_impl/cms_fingerprint_module.py) that the
                        # generic label/cve/severity line above doesn't
                        # surface on its own -- fill those in inline rather
                        # than falling through to the raw-json branch below.
                        extra = ""
                        if label == "cms_detected":
                            cms, ver = d.get("cms"), d.get("version")
                            extra = f" — {cms}{f' {ver}' if ver else ' (version not determined)'}"
                        elif label == "cms_admin_panel_found":
                            path = d.get("login_path") or d.get("admin_path")
                            extra = f" — {path} (status {d.get('login_status') or d.get('admin_status')})"
                        elif label == "wordpress_user_enumeration":
                            extra = f" — usernames: {', '.join(d.get('usernames', []))}"
                        lines.append(f"  - `{label}`{cve_txt}{extra} severity={sev}{vtxt} — source: {f['source_tool']}")
                    elif "banner" in d:
                        lines.append(f"  - banner: `{d['banner']}` — source: {f['source_tool']}")
                    else:
                        lines.append(f"  - {json.dumps(d)} — source: {f['source_tool']}")

            if not any(detail.get(k) for k in ("technology", "directory", "share", "finding")):
                lines.append("- _No additional data gathered for this service._")

            lines.append("")

        # --- Findings not tied to a port (host-wide) ---
        host_wide_findings = [f for f in findings if f["data"].get("port") is None]
        if host_wide_findings:
            lines.append("## Host-Wide Findings")
            lines.append("")
            for f in host_wide_findings:
                d = f["data"]
                label = d.get("finding") or d.get("cve") or json.dumps(d)
                sev = d.get("severity", "")
                lines.append(f"- `{label}` severity={sev} — source: {f['source_tool']}")
            lines.append("")

        # --- Shares not tied to a specific port (e.g. smbclient output) ---
        host_wide_shares = [f for f in shares if f["data"].get("port") is None]
        if host_wide_shares:
            lines.append("## SMB Shares")
            lines.append("")
            lines.append("| Share | Type | Comment |")
            lines.append("|-------|------|---------|")
            for f in host_wide_shares:
                d = f["data"]
                lines.append(f"| {d.get('name', '')} | {d.get('type', '')} | {d.get('comment') or ''} |")
            lines.append("")

        # --- Credentials ---
        if credentials:
            lines.append("## Credentials Found")
            lines.append("")
            lines.append("| Username | Password | Source |")
            lines.append("|----------|----------|--------|")
            for f in credentials:
                cred = f["data"].get("credential", {})
                lines.append(
                    f"| {cred.get('username', '')} | {cred.get('password', '')} | {f['source_tool']} |"
                )
            lines.append("")

        # --- Module execution status ---
        lines.append("## Module Execution Status")
        lines.append("")
        lines.append("| Module | Status | Started | Finished |")
        lines.append("|--------|--------|---------|----------|")
        for m in self.kb.module_status(self.host):
            lines.append(
                f"| {m['module']} | {m['status']} | {m['started_at']} | {m.get('finished_at') or ''} |"
            )
        lines.append("")

        path = self.output_dir / "report.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write("\n".join(lines))
        return path
