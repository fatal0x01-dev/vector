"""
Feroxbuster module
===================
Directory/content brute forcing against discovered HTTP(S) ports.
Uses --json for structured, line-delimited JSON output.

Baseline fallback
------------------
The previous version of this module hard-pointed at a SecLists path
(DEFAULT_WORDLIST below) and did nothing else -- on any box without
SecLists installed (not a given; it's a large, separate, optional
package even on Kali), `--wordlist <missing path>` makes feroxbuster
exit immediately with no results, and the module silently produced
nothing. That defeats the actual point of running feroxbuster at all:
getting *some* read on hidden paths/panels/backups on every HTTP(S)
port, every run, regardless of what's installed -- "a basic scan to
get a lay of the land" even in the worst case.

So: if the configured wordlist exists on disk, this still uses it
(SecLists' raft-small-directories.txt is a much deeper list and is
worth using when it's there). If it doesn't, this module writes a
built-in baseline list (BASELINE_PATHS below) to a temp file and scans
with that instead -- so feroxbuster always runs, and you always get a
baseline result even on a bare install. This is deliberately a SHORT,
high-signal list (common admin/login panels, source-control and env
leaks, backup/config file names, API/monitoring endpoints) -- a quick
triage pass, not a substitute for a real content-discovery wordlist
when one is available. Swap BASELINE_PATHS or point DEFAULT_WORDLIST
at a different file for deeper coverage.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from core.module_base import Module, ModuleResult
from core.registry import register_implementation

logger = logging.getLogger("modules.feroxbuster")

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"

# Short and deliberate (see module docstring): common admin/login
# panels, source-control and secret/config leaks, backup file names,
# and API/monitoring endpoints that are worth checking on literally
# every web target regardless of what CMS or framework it turns out to
# be. CMS-specific paths (wp-admin, wp-login.php, etc.) are deliberately
# NOT duplicated here -- modules_impl/cms_fingerprint_module.py already
# checks those directly once it identifies the CMS; this list stays
# generic.
BASELINE_PATHS = [
    # admin/login panels
    "admin", "admin/login", "administrator", "login", "wp-login.php",
    "user/login", "manager/html", "phpmyadmin", "adminer.php",
    # source control / secrets / config leaks
    ".git/HEAD", ".git/config", ".svn/entries", ".env", ".env.bak",
    "config.php", "config.php.bak", "wp-config.php.bak", "web.config",
    ".aws/credentials", "id_rsa", ".ssh/id_rsa",
    # backups / archives left behind
    "backup.zip", "backup.sql", "backup.tar.gz", "site.zip", "www.zip",
    "database.sql", "dump.sql",
    # info-leaking / debug endpoints
    "phpinfo.php", "info.php", "test.php", "debug", "server-status",
    "server-info", ".well-known/security.txt",
    # API / monitoring / ops surfaces
    "api", "api/v1", "swagger", "swagger.json", "swagger-ui.html",
    "actuator", "actuator/health", "metrics", "status", "health",
    # standard crawl/discovery files
    "robots.txt", "sitemap.xml", "crossdomain.xml",
]


@register_implementation("feroxbuster")
class FeroxbusterModule(Module):
    default_fact_type = "directory"
    timeout_seconds = 600

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        return service_fact.get("service", "").lower() in ("http", "https", "http-alt", "https-alt")

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        # NOTE: this returns the command assuming DEFAULT_WORDLIST
        # exists, for interface consistency / standalone use. run()
        # below is what actually checks and falls back to the baseline
        # list, since that needs to materialize a temp file first.
        host = target_ctx["host"]
        port = target_ctx["port"]
        scheme = "https" if "https" in target_ctx.get("service", "") else "http"
        url = f"{scheme}://{host}:{port}"
        return self._base_command(url, DEFAULT_WORDLIST)

    @staticmethod
    def _base_command(url: str, wordlist_path: str) -> list[str]:
        return [
            "feroxbuster",
            "--url", url,
            "--wordlist", wordlist_path,
            "--json",
            "--quiet",
            "--no-state",
        ]

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            # feroxbuster emits several message "type"s; we only care about
            # the per-URL response results
            if record.get("type") != "response":
                continue

            status = record.get("status")
            url = record.get("url")
            if status is None or url is None:
                continue

            facts.append({
                "type": "directory",
                "data": {
                    "port": target_ctx["port"],
                    "path": url,
                    "status": status,
                    "content_length": record.get("content_length"),
                },
            })
        return facts

    def run(self, target_ctx: dict[str, Any]) -> ModuleResult:
        host = target_ctx["host"]
        port = target_ctx["port"]
        scheme = "https" if "https" in target_ctx.get("service", "") else "http"
        url = f"{scheme}://{host}:{port}"
        log_path = self._log_path(host)

        using_baseline = not Path(DEFAULT_WORDLIST).is_file()
        baseline_tmp_path: str | None = None
        if using_baseline:
            # SecLists (or whatever DEFAULT_WORDLIST points at) isn't
            # installed -- write the baseline list to a temp file and
            # scan with that instead, so this module always produces a
            # "lay of the land" result rather than silently doing
            # nothing. See module docstring.
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", prefix="vector-ferox-baseline-", delete=False
            ) as tmp:
                tmp.write("\n".join(BASELINE_PATHS) + "\n")
                baseline_tmp_path = tmp.name
            wordlist_path = baseline_tmp_path
        else:
            wordlist_path = DEFAULT_WORDLIST

        note = ""
        if using_baseline:
            note = (
                f"'{DEFAULT_WORDLIST}' not found -- used the built-in "
                f"{len(BASELINE_PATHS)}-path baseline list instead of a full wordlist"
            )
            # ModuleResult.error is only surfaced by the controller when
            # a run FAILS (see core/controller.py _store_result), and
            # isn't persisted by the knowledge base at all -- so a
            # successful-but-degraded run like this one needs its own
            # visible signal, not that field. Goes to the console/log
            # (an unattended run still gets to see it) and into the
            # per-invocation log file itself via _write_log's `note`.
            logger.info("[%s] feroxbuster: %s", host, note)

        cmd = self._base_command(url, wordlist_path)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_seconds)
            self._write_log(log_path, cmd, proc.stdout, proc.stderr, proc.returncode, note=note)
            raw_facts = self.parse_output(proc.stdout, target_ctx)
            facts = [self._to_envelope(f, host) for f in raw_facts]

            return ModuleResult(
                module_name=self.name, host=host, success=True,
                facts=facts, log_path=str(log_path),
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
        except Exception as e:  # noqa: BLE001
            return ModuleResult(module_name=self.name, host=host, success=False, error=str(e))
        finally:
            if baseline_tmp_path is not None:
                Path(baseline_tmp_path).unlink(missing_ok=True)
