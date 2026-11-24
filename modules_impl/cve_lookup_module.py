"""
CVE lookup module
==================
Takes the product/version fingerprint nmap -sV already extracted for a
service (core/..., see nmap_module.py) and checks it against known
vulnerabilities via two independent sources:

  1. searchsploit (exploitdb) -- local, offline, fast. Flags exploit-db
     entries whose title/metadata match the product+version search terms.
     Requires the `exploitdb` package (`apt install exploitdb` on
     Kali/Debian) so `searchsploit` is on $PATH.

  2. NVD REST API (services.nvd.nist.gov) -- online keyword search
     against the full CVE corpus, not just entries with a public exploit.
     No API key required, but anonymous requests are rate-limited to
     5 req/30s; set NVD_API_KEY in the environment (free key:
     https://nvd.nist.gov/developers/request-an-api-key) to raise that
     to 50 req/30s. The module self-throttles to stay under the
     anonymous limit either way.

READ THIS BEFORE TRUSTING THE OUTPUT
-------------------------------------
Both lookups are keyword/text matches against "<product> <version>", not
authoritative CPE (Common Platform Enumeration) version-range matching.
A hit means "this product/version string appears in a CVE or exploit-db
record" -- not "this exact build is confirmed vulnerable". Every fact
this module produces is a *lead* to triage manually: open the advisory,
confirm the actual affected version range, confirm the service is
reachable/exploitable in context. That's why these facts carry
"verified": False except where exploitdb itself marks an exploit
verified -- contrast with nuclei_module.py, whose findings ARE live
confirmed matches against the real target.

Field names in the searchsploit --json parsing below (Title, EDB-ID,
Codes, Path, Verified) match exploitdb's schema as of its 2024+
releases. If your installed searchsploit is much older or the schema
has since changed, verify with:
    searchsploit --json openssh 7.4 | python3 -m json.tool
and adjust the .get() keys in parse_output() if they differ -- don't
assume this module's field mapping is correct for your exact version
without checking once after install.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from core.module_base import Module, ModuleResult
from core.registry import register_implementation

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Anonymous NVD rate limit is 5 requests/30s. Self-throttle to stay
# safely under it when several fingerprinted ports on one host trigger
# this module back-to-back during a single run.
NVD_MIN_INTERVAL_SECONDS = 6.5
_last_nvd_request_at = 0.0


@register_implementation("searchsploit")
class CveLookupModule(Module):
    name = "searchsploit"
    default_fact_type = "finding"
    timeout_seconds = 60

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        # Mirrors modules/cve.yaml's has_version trigger -- kept here too
        # for standalone/test use per the Module contract in module_base.py.
        return bool(service_fact.get("product")) and bool(service_fact.get("version"))

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        product = target_ctx.get("product") or ""
        version = target_ctx.get("version") or ""
        # Separate argv entries, not a joined string: searchsploit ANDs
        # multiple search terms together, and passing them as distinct
        # list items (not shell=True) means there's nothing to quote or
        # escape regardless of what nmap put in product/version.
        return ["searchsploit", "--json", product, version]

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []
        if not raw_stdout.strip():
            return facts

        try:
            parsed = json.loads(raw_stdout)
        except json.JSONDecodeError:
            return facts

        # "RESULTS_SHELLCODE" entries are deliberately ignored here -- they
        # aren't service/CVE matches, just raw shellcode listings.
        for entry in parsed.get("RESULTS_EXPLOIT", []) or []:
            codes = entry.get("Codes") or ""
            cves = CVE_RE.findall(codes)
            facts.append({
                "type": "finding",
                "data": {
                    "port": target_ctx.get("port"),
                    "finding": "exploitdb_match",
                    "cve": cves[0].upper() if cves else None,
                    "all_cves": [c.upper() for c in cves] if len(cves) > 1 else None,
                    "edb_id": entry.get("EDB-ID"),
                    "title": entry.get("Title"),
                    "path": entry.get("Path"),
                    "severity": "unknown",  # exploitdb doesn't grade severity
                    "verified": str(entry.get("Verified")) == "1",
                    "source": "exploitdb",
                },
            })
        return facts

    # ------------------------------------------------------------------
    # Overrides the base class's single-subprocess run(): this module
    # combines a subprocess call (searchsploit) with an HTTP call (NVD),
    # same pattern ssh_banner_module.py / ftp_anon_module.py use to
    # override run() for non-default execution.
    # ------------------------------------------------------------------

    def run(self, target_ctx: dict[str, Any]) -> ModuleResult:
        host = target_ctx["host"]
        product = target_ctx.get("product")
        version = target_ctx.get("version")
        log_path = self._log_path(host)

        if not product or not version:
            # Shouldn't happen via normal dispatch (the registry only
            # routes here when both are present) -- stays safe if this
            # module is ever invoked standalone/directly.
            return ModuleResult(
                module_name=self.name, host=host, success=True, facts=[],
                error="no product/version fingerprint available -- nothing to look up",
            )

        all_facts: list[dict[str, Any]] = []
        errors: list[str] = []
        log_sections: list[str] = []

        # --- Source 1: searchsploit / exploitdb (offline) ---
        cmd = self.build_command(target_ctx)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_seconds)
            log_sections.append(
                f"$ {' '.join(cmd)}\n[exit code: {proc.returncode}]\n"
                f"--- stdout ---\n{proc.stdout or '(empty)'}\n--- stderr ---\n{proc.stderr or '(empty)'}"
            )
            raw_facts = self.parse_output(proc.stdout, target_ctx)
            all_facts.extend(self._to_envelope(f, host) for f in raw_facts)
        except FileNotFoundError:
            msg = "searchsploit not found on $PATH -- install the 'exploitdb' package"
            errors.append(msg)
            log_sections.append(f"$ {' '.join(cmd)}\n[SKIPPED: {msg}]")
        except subprocess.TimeoutExpired:
            msg = f"searchsploit timed out after {self.timeout_seconds}s"
            errors.append(msg)
            log_sections.append(f"$ {' '.join(cmd)}\n[TIMEOUT]")
        except Exception as e:  # noqa: BLE001 -- any searchsploit failure shouldn't abort the NVD lookup
            errors.append(f"searchsploit failed: {e}")
            log_sections.append(f"$ {' '.join(cmd)}\n[ERROR: {e}]")

        # --- Source 2: NVD keyword search (online) ---
        try:
            nvd_facts, nvd_log = self._query_nvd(product, version, target_ctx)
            all_facts.extend(self._to_envelope(f, host) for f in nvd_facts)
            log_sections.append(nvd_log)
        except Exception as e:  # noqa: BLE001 -- network/API failure shouldn't lose the searchsploit results above
            errors.append(f"NVD lookup failed: {e}")
            log_sections.append(f"$ GET {NVD_ENDPOINT} (keywordSearch={product} {version})\n[ERROR: {e}]")

        self._write_log(log_path, ["searchsploit", "+", "nvd-api"], "\n\n".join(log_sections), "", 0)

        # Only fail outright if BOTH sources errored; a single source
        # being unavailable (no searchsploit installed, NVD unreachable
        # on an airgapped engagement) still counts as a useful partial run.
        success = len(errors) < 2
        return ModuleResult(
            module_name=self.name, host=host, success=success,
            facts=all_facts, log_path=str(log_path),
            error="; ".join(errors) if errors else None,
        )

    @staticmethod
    def _query_nvd(product: str, version: str, target_ctx: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
        global _last_nvd_request_at

        elapsed = time.monotonic() - _last_nvd_request_at
        if elapsed < NVD_MIN_INTERVAL_SECONDS:
            time.sleep(NVD_MIN_INTERVAL_SECONDS - elapsed)

        query = urllib.parse.urlencode({
            "keywordSearch": f"{product} {version}",
            "resultsPerPage": 20,
        })
        url = f"{NVD_ENDPOINT}?{query}"
        req = urllib.request.Request(url, headers={"User-Agent": "vector-recon-cve-module"})
        api_key = os.environ.get("NVD_API_KEY")
        if api_key:
            req.add_header("apiKey", api_key)

        _last_nvd_request_at = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code == 429:
                # One backoff-and-retry; a second 429 propagates to the caller.
                time.sleep(10)
                with urllib.request.urlopen(req, timeout=20) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
            else:
                raise

        parsed = json.loads(body)
        facts: list[dict[str, Any]] = []
        for item in parsed.get("vulnerabilities", []) or []:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            descriptions = cve.get("descriptions", []) or []
            desc_en = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")

            severity, score = None, None
            metrics = cve.get("metrics", {}) or {}
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    cvss_data = metrics[key][0].get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    severity = (metrics[key][0].get("baseSeverity") or cvss_data.get("baseSeverity") or "")
                    severity = severity.lower() if severity else None
                    break

            facts.append({
                "type": "finding",
                "data": {
                    "port": target_ctx.get("port"),
                    "cve": cve_id,
                    "severity": severity or "unknown",
                    "cvss_score": score,
                    "description": (desc_en[:200] + "...") if len(desc_en) > 200 else desc_en,
                    "verified": False,  # keyword match only -- not CPE-confirmed, triage manually
                    "source": "nvd",
                },
            })

        log = f"$ GET {url}\n[{len(facts)} CVE(s) matched]"
        return facts, log
