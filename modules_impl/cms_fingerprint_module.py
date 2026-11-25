"""
Web server / CMS fingerprint module
=====================================
Entry-point angle: "there's a web server here" (what whatweb/feroxbuster
already tell you) is not the same question as "what's actually running
it and where's the door in" -- a stock Apache/nginx banner says
nothing about whether there's a CMS behind it with its own login panel,
its own version-specific CVEs, and its own default enumeration
endpoints. This module answers that second question directly:

  1. Reads the `Server`/`X-Powered-By` response headers -> a
     `webserver` fact (separate from whatweb's `technology` fact,
     which is plugin-signature based; this is the literal header
     value, which whatweb doesn't currently surface as its own fact).

  2. Fingerprints the CMS, if any, via (in order of reliability):
       - the `<meta name="generator" content="...">` tag, when present
         (most CMSs emit this; cheapest and most direct signal)
       - WordPress-specific: `?ver=X.Y.Z` query strings nearly every
         WP install appends to its own bundled JS/CSS asset URLs
         (wp-includes/wp-content paths) -- a well-known, passive,
         read-the-homepage version fingerprint that works even when
         the generator tag has been stripped (a common, token
         hardening step that people assume is sufficient on its own)
       - falling back to GET /readme.html, which stock WordPress ships
         with a `Version X.Y.Z` line unless someone deleted it

  3. WordPress specifically (the example in the request), beyond
     version: checks whether `/wp-login.php` and `/wp-admin/` are
     reachable (confirms the admin entry point exists and whether it's
     gating behind a login redirect, which is the expected/default
     state -- reachable doesn't mean misconfigured, it means "this is
     where the door is"), and checks the REST API's
     `/wp-json/wp/v2/users` endpoint, which WordPress exposes
     unauthenticated by default and which leaks every username with a
     public post -- a direct feed into the default-creds/hydra module
     (modules_impl/default_creds_module.py) once you have real
     usernames instead of a guessed "admin".

  4. If a CMS + version was found, runs the same searchsploit lookup
     cve_lookup_module.py already does (same keyword-match caveat
     applies -- see that module's docstring for why these are leads to
     triage, not confirmed findings) so a dated CMS install surfaces
     its own CVE leads the same way a dated service version does.

  5. Joomla and Drupal get a lighter version of the same treatment
     (generator-tag version + known admin-login path) -- the signature
     table below (CMS_SIGNATURES) is what to extend for another CMS,
     not a reason to add a new module.

All HTTP calls use stdlib `urllib` (no new external binary or Python
dependency), the same approach cve_lookup_module.py already uses for
its NVD query. TLS verification is intentionally disabled (CERT_NONE)
the same way tls_audit_module.py disables it -- this module fingerprints
whatever is actually answering, self-signed cert or not; the TLS audit
module is what reports on the certificate itself.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from typing import Any, Optional
from urllib.parse import urljoin

from core.module_base import Module, ModuleResult
from core.registry import register_implementation

HTTP_TIMEOUT_SECONDS = 10
MAX_BODY_BYTES = 300_000  # don't pull down a huge page body just to regex it
USER_AGENT = "Mozilla/5.0 (compatible; vector-recon/1.0)"

GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE
)
WP_ASSET_VERSION_RE = re.compile(
    r'(?:wp-content|wp-includes)/[^"\'<>\s]+[?&]ver=([0-9]+(?:\.[0-9]+){1,3})', re.IGNORECASE
)
WP_README_VERSION_RE = re.compile(r'Version\s+([0-9]+(?:\.[0-9]+){1,3})', re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

CMS_SIGNATURES: dict[str, dict[str, Any]] = {
    "wordpress": {
        "body_indicators": ["wp-content/", "wp-includes/", "/wp-json/"],
        "generator_prefix": "wordpress",
        "login_path": "/wp-login.php",
        "admin_path": "/wp-admin/",
    },
    "joomla": {
        "body_indicators": ["/media/jui/", "com_content", "Joomla!"],
        "generator_prefix": "joomla",
        "login_path": "/administrator/index.php",
        "admin_path": "/administrator/",
    },
    "drupal": {
        "body_indicators": ["Drupal.settings", "/sites/default/files/", "/sites/all/"],
        "generator_prefix": "drupal",
        "login_path": "/user/login",
        "admin_path": "/user/login",
    },
}


@register_implementation("cms-fingerprint")
class CmsFingerprintModule(Module):
    name = "cms-fingerprint"
    default_fact_type = "finding"
    timeout_seconds = 60

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        return service_fact.get("service", "").lower() in ("http", "https", "http-alt", "https-alt")

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        # Documented for interface consistency -- run() below makes the
        # actual sequence of HTTP requests via urllib, same pattern as
        # tls_audit_module.py overriding run() for non-subprocess work.
        scheme = "https" if "https" in str(target_ctx.get("service", "")) else "http"
        return ["GET", f"{scheme}://{target_ctx['host']}:{target_ctx['port']}/"]

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        return []  # run() builds facts directly -- see module docstring

    def run(self, target_ctx: dict[str, Any]) -> ModuleResult:
        host, port = target_ctx["host"], target_ctx["port"]
        scheme = "https" if "https" in str(target_ctx.get("service", "")) else "http"
        base_url = f"{scheme}://{host}:{port}"
        log_path = self._log_path(host)
        log_lines: list[str] = []
        facts: list[dict[str, Any]] = []

        status, headers, body = self._get(base_url + "/", log_lines)
        if status is None:
            self._write_log(log_path, ["GET", base_url + "/"], "\n".join(log_lines), "", 0)
            return ModuleResult(module_name=self.name, host=host, success=True, facts=[], log_path=str(log_path))

        server_header = headers.get("server") if headers else None
        powered_by = headers.get("x-powered-by") if headers else None
        if server_header or powered_by:
            facts.append({
                "type": "webserver",
                "data": {"port": port, "server": server_header, "x_powered_by": powered_by},
            })

        cms_name, generator_raw = self._detect_cms(body)
        if cms_name:
            version = self._extract_generator_version(generator_raw, cms_name)

            if cms_name == "wordpress":
                if not version:
                    version = self._best_wp_asset_version(body)
                if not version:
                    version = self._wp_readme_version(base_url, log_lines)
                self._probe_wordpress(base_url, port, facts, log_lines)
            elif cms_name in ("joomla", "drupal"):
                self._probe_generic_admin(base_url, port, cms_name, log_lines, facts)

            facts.append({
                "type": "finding",
                "data": {
                    "port": port, "finding": "cms_detected", "severity": "info", "verified": True,
                    "cms": cms_name, "version": version,
                },
            })

            if version:
                self._searchsploit_lookup(cms_name, version, port, facts, log_lines)

        self._write_log(log_path, ["GET (multiple)", base_url], "\n".join(log_lines), "", 0)
        envelopes = [self._to_envelope(f, host) for f in facts]
        return ModuleResult(module_name=self.name, host=host, success=True, facts=envelopes, log_path=str(log_path))

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    @staticmethod
    def _get(url: str, log_lines: list[str]) -> tuple[Optional[int], Optional[dict[str, str]], str]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS, context=ctx) as resp:
                raw = resp.read(MAX_BODY_BYTES)
                body = raw.decode("utf-8", errors="replace")
                headers = {k.lower(): v for k, v in resp.getheaders()}
                log_lines.append(f"GET {url} -> {resp.status} ({len(raw)} bytes)")
                return resp.status, headers, body
        except urllib.error.HTTPError as e:
            # A non-2xx is still a useful, parseable response (e.g. a
            # 403 on /wp-admin/ still tells us the path exists).
            try:
                raw = e.read(MAX_BODY_BYTES)
                body = raw.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                body = ""
            headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            log_lines.append(f"GET {url} -> {e.code} (HTTPError)")
            return e.code, headers, body
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
            log_lines.append(f"GET {url} -> ERROR: {e}")
            return None, None, ""

    # ------------------------------------------------------------------
    # CMS detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_cms(body: str) -> tuple[Optional[str], Optional[str]]:
        generator_match = GENERATOR_RE.search(body)
        generator_raw = generator_match.group(1) if generator_match else None

        if generator_raw:
            lowered = generator_raw.lower()
            for cms_name, sig in CMS_SIGNATURES.items():
                if sig["generator_prefix"] in lowered:
                    return cms_name, generator_raw

        # Generator tag absent/stripped -- fall back to body indicator strings.
        for cms_name, sig in CMS_SIGNATURES.items():
            if any(ind in body for ind in sig["body_indicators"]):
                return cms_name, generator_raw

        return None, None

    @staticmethod
    def _extract_generator_version(generator_raw: Optional[str], cms_name: str) -> Optional[str]:
        if not generator_raw:
            return None
        match = re.search(r"([0-9]+(?:\.[0-9]+){1,3})", generator_raw)
        return match.group(1) if match else None

    @staticmethod
    def _best_wp_asset_version(body: str) -> Optional[str]:
        versions = WP_ASSET_VERSION_RE.findall(body)
        if not versions:
            return None

        def as_tuple(v: str) -> tuple[int, ...]:
            return tuple(int(p) for p in v.split("."))

        # WP core bundles its own version onto its own asset URLs; a
        # bundled plugin/theme may stamp its OWN version the same way,
        # so take the version that appears most often rather than the
        # simple max -- the core version tends to repeat across many
        # wp-includes/* asset tags, whereas a single plugin's version
        # string appears on just that plugin's handful of assets.
        from collections import Counter
        counts = Counter(versions)
        return counts.most_common(1)[0][0]

    @classmethod
    def _wp_readme_version(cls, base_url: str, log_lines: list[str]) -> Optional[str]:
        status, _, body = cls._get(urljoin(base_url + "/", "readme.html"), log_lines)
        if status != 200 or not body:
            return None
        match = WP_README_VERSION_RE.search(body)
        return match.group(1) if match else None

    @classmethod
    def _probe_wordpress(cls, base_url: str, port: int, facts: list[dict[str, Any]], log_lines: list[str]) -> None:
        sig = CMS_SIGNATURES["wordpress"]

        login_status, _, _ = cls._get(urljoin(base_url + "/", sig["login_path"].lstrip("/")), log_lines)
        admin_status, admin_headers, _ = cls._get(urljoin(base_url + "/", sig["admin_path"].lstrip("/")), log_lines)
        if login_status == 200 or admin_status in (200, 302, 403):
            facts.append({
                "type": "finding",
                "data": {
                    "port": port, "finding": "cms_admin_panel_found", "severity": "low", "verified": True,
                    "cms": "wordpress", "login_path": sig["login_path"], "admin_path": sig["admin_path"],
                    "login_status": login_status, "admin_status": admin_status,
                },
            })

        users_status, _, users_body = cls._get(
            urljoin(base_url + "/", "wp-json/wp/v2/users"), log_lines
        )
        if users_status == 200 and users_body:
            try:
                users = json.loads(users_body)
            except json.JSONDecodeError:
                users = None
            if isinstance(users, list) and users:
                names = [u.get("slug") or u.get("name") for u in users if isinstance(u, dict)]
                names = [n for n in names if n][:10]
                if names:
                    facts.append({
                        "type": "finding",
                        "data": {
                            "port": port, "finding": "wordpress_user_enumeration", "severity": "medium",
                            "verified": True, "usernames": names,
                        },
                    })

    @classmethod
    def _probe_generic_admin(
        cls, base_url: str, port: int, cms_name: str, log_lines: list[str], facts: list[dict[str, Any]]
    ) -> None:
        sig = CMS_SIGNATURES[cms_name]
        status, _, _ = cls._get(urljoin(base_url + "/", sig["admin_path"].lstrip("/")), log_lines)
        if status in (200, 302, 403):
            facts.append({
                "type": "finding",
                "data": {
                    "port": port, "finding": "cms_admin_panel_found", "severity": "low", "verified": True,
                    "cms": cms_name, "admin_path": sig["admin_path"], "admin_status": status,
                },
            })

    # ------------------------------------------------------------------
    # CVE lead for the detected CMS version (searchsploit only -- see
    # cve_lookup_module.py for the full two-source version against
    # nmap-fingerprinted services; this is the same offline source
    # applied to a CMS version instead of a protocol version, with the
    # identical "keyword match, not CPE-confirmed" caveat).
    # ------------------------------------------------------------------

    @staticmethod
    def _searchsploit_lookup(
        cms_name: str, version: str, port: int, facts: list[dict[str, Any]], log_lines: list[str]
    ) -> None:
        cmd = ["searchsploit", "--json", cms_name, version]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            log_lines.append(f"$ {' '.join(cmd)}\n{proc.stdout[:2000]}")
        except FileNotFoundError:
            log_lines.append(f"$ {' '.join(cmd)}\n[SKIPPED: searchsploit not found on $PATH]")
            return
        except Exception as e:  # noqa: BLE001
            log_lines.append(f"$ {' '.join(cmd)}\n[ERROR: {e}]")
            return

        try:
            parsed = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError:
            return

        for entry in parsed.get("RESULTS_EXPLOIT", []) or []:
            codes = entry.get("Codes") or ""
            cves = CVE_RE.findall(codes)
            facts.append({
                "type": "finding",
                "data": {
                    "port": port, "finding": "exploitdb_match",
                    "cve": cves[0].upper() if cves else None,
                    "edb_id": entry.get("EDB-ID"), "title": entry.get("Title"),
                    "path": entry.get("Path"), "severity": "unknown",
                    "verified": str(entry.get("Verified")) == "1",
                    "source": "exploitdb", "cms": cms_name, "cms_version": version,
                },
            })
