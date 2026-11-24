"""
TLS/SSL audit module
=====================
Entry-point angle: a TLS listener often leaks more than it should --
an expired or self-signed certificate nobody rotated, SANs that reveal
internal hostnames, a server still willing to downgrade to a
deprecated protocol (TLS 1.0/1.1, deprecated outright per RFC 8996).
This is frequently the very first thing checked in an external
assessment. It fires on ANY TLS-wrapped port nmap identified -- not
just 443/8443 -- via the `tunnel: ssl` trigger (modules/tls.yaml),
which nmap -sV sets whenever it detects an SSL wrapper regardless of
which protocol is running inside it (ssl/http, ssl/smtp, ssl/imap,
a TLS-wrapped custom app port, ...). See nmap_module.py for where
`tunnel` is captured.

Certificate details (subject, issuer, validity dates) are pulled via
`openssl s_client` + `openssl x509`, not Python's stdlib `ssl` module.
Reason: `ssl.SSLSocket.getpeercert()` only returns the parsed dict form
of a certificate when it passed verification -- which is exactly the
case this module doesn't have, since it deliberately uses CERT_NONE
(we WANT to see self-signed/expired/untrusted certs, not have the
connection refuse to complete because of them). `openssl x509 -noout
-subject -issuer -dates` parses any certificate regardless of trust,
which is what's actually needed here. Stdlib `ssl` IS used below for
the weak-protocol handshake probes, where only connect-or-fail matters
and no certificate parsing is involved.

This is intentionally a quick signal, not a full TLS audit -- it does
not sweep every cipher suite the way testssl.sh/sslscan/sslyze do. If
one of those is installed, run it against any `port` fact where
`tunnel == "ssl"` for the deeper sweep; this module's findings are the
cue for which ports deserve that follow-up, not a replacement for it.
"""

from __future__ import annotations

import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Any, Optional

from core.module_base import Module, ModuleResult
from core.registry import register_implementation

# TLS 1.0/1.1 are deprecated (RFC 8996); a server still willing to
# negotiate them is itself the finding.
WEAK_PROTOCOLS = [
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
]


@register_implementation("tls-audit")
class TlsAuditModule(Module):
    name = "tls-audit"
    default_fact_type = "finding"
    timeout_seconds = 30

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        return str(service_fact.get("tunnel", "")).lower() == "ssl"

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        # Documented for interface consistency -- run() below issues the
        # actual sequence of openssl + stdlib-ssl calls.
        return ["openssl", "s_client", "-connect", f"{target_ctx['host']}:{target_ctx['port']}"]

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        return []  # run() builds facts directly -- see module docstring

    def run(self, target_ctx: dict[str, Any]) -> ModuleResult:
        host, port = target_ctx["host"], target_ctx["port"]
        log_path = self._log_path(host)
        log_lines: list[str] = []
        facts: list[dict[str, Any]] = []

        # --- Certificate details via openssl (handles untrusted/self-signed/expired certs) ---
        cert_info = self._get_cert_info(host, port, log_lines)
        if cert_info:
            facts.append({
                "type": "finding",
                "data": {"port": port, "finding": "tls_certificate_info", "severity": "info",
                          "verified": True, **cert_info},
            })
            if cert_info.get("expired"):
                facts.append({
                    "type": "finding",
                    "data": {"port": port, "finding": "tls_certificate_expired",
                              "severity": "medium", "verified": True},
                })
            if cert_info.get("self_signed"):
                facts.append({
                    "type": "finding",
                    "data": {"port": port, "finding": "tls_certificate_self_signed",
                              "severity": "low", "verified": True},
                })

        # --- Negotiated protocol/cipher via stdlib ssl (no cert parsing needed here) ---
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout_seconds) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    negotiated_version = tls_sock.version()
                    negotiated_cipher = tls_sock.cipher()
            log_lines.append(f"negotiated: {negotiated_version} {negotiated_cipher}")
            facts.append({
                "type": "finding",
                "data": {
                    "port": port, "finding": "tls_negotiated_protocol", "severity": "info", "verified": True,
                    "protocol": negotiated_version,
                    "cipher": negotiated_cipher[0] if negotiated_cipher else None,
                },
            })
        except Exception as e:  # noqa: BLE001
            log_lines.append(f"default TLS negotiation failed: {e}")

        # --- Explicit deprecated-protocol probes ---
        for label, version in WEAK_PROTOCOLS:
            accepted, detail = self._probe_protocol(host, port, version)
            log_lines.append(f"{label}: {'ACCEPTED' if accepted else 'rejected'} ({detail})")
            if accepted:
                facts.append({
                    "type": "finding",
                    "data": {"port": port, "finding": "weak_tls_protocol_accepted", "protocol": label,
                              "severity": "medium", "verified": True},
                })

        self._write_log(log_path, ["openssl+ssl", host, str(port)], "\n".join(log_lines), "", 0)
        envelopes = [self._to_envelope(f, host) for f in facts]
        return ModuleResult(module_name=self.name, host=host, success=True, facts=envelopes, log_path=str(log_path))

    # ------------------------------------------------------------------

    @staticmethod
    def _get_cert_info(host: str, port: int, log_lines: list[str]) -> Optional[dict[str, Any]]:
        # `echo | openssl s_client -connect host:port` is the standard
        # recipe for a non-interactive cert fetch: closing stdin
        # immediately gives openssl EOF so it prints the handshake/cert
        # info and exits rather than waiting for application data.
        s_client_cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host]
        try:
            proc = subprocess.run(s_client_cmd, input="", capture_output=True, text=True, timeout=15)
        except Exception as e:  # noqa: BLE001
            log_lines.append(f"$ {' '.join(s_client_cmd)}\n[ERROR: {e}]")
            return None

        if "BEGIN CERTIFICATE" not in proc.stdout:
            log_lines.append(f"$ {' '.join(s_client_cmd)}\n[no certificate in response]")
            return None

        pem_start = proc.stdout.index("-----BEGIN CERTIFICATE-----")
        pem_end = proc.stdout.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
        pem = proc.stdout[pem_start:pem_end]

        x509_cmd = ["openssl", "x509", "-noout", "-subject", "-issuer", "-startdate", "-enddate"]
        try:
            x509_proc = subprocess.run(x509_cmd, input=pem, capture_output=True, text=True, timeout=10)
        except Exception as e:  # noqa: BLE001
            log_lines.append(f"$ {' '.join(x509_cmd)}\n[ERROR: {e}]")
            return None

        log_lines.append(f"$ {' '.join(s_client_cmd)} | {' '.join(x509_cmd)}\n{x509_proc.stdout}")

        subject = issuer = not_before = not_after = None
        for line in x509_proc.stdout.splitlines():
            if line.startswith("subject="):
                subject = line[len("subject="):].strip()
            elif line.startswith("issuer="):
                issuer = line[len("issuer="):].strip()
            elif line.startswith("notBefore="):
                not_before = line[len("notBefore="):].strip()
            elif line.startswith("notAfter="):
                not_after = line[len("notAfter="):].strip()

        expired = False
        if not_after:
            expiry = TlsAuditModule._parse_openssl_date(not_after)
            if expiry and expiry < datetime.now(timezone.utc):
                expired = True

        self_signed = bool(subject and issuer and subject == issuer)

        return {
            "subject": subject, "issuer": issuer,
            "not_before": not_before, "not_after": not_after,
            "expired": expired, "self_signed": self_signed,
        }

    @staticmethod
    def _parse_openssl_date(value: str) -> Optional[datetime]:
        # openssl prints e.g. "Jan  1 00:00:00 2030 GMT" (note the
        # double space before single-digit days) -- normalize whitespace
        # rather than special-case the day-padding format.
        cleaned = re.sub(r"\s+", " ", value.replace("GMT", "")).strip()
        try:
            return datetime.strptime(cleaned, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _probe_protocol(self, host: str, port: int, version: "ssl.TLSVersion") -> tuple[bool, str]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((host, port), timeout=self.timeout_seconds) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    pass
            return True, "handshake succeeded"
        except ssl.SSLError as e:
            return False, str(e)
        except Exception as e:  # noqa: BLE001
            return False, f"connection error: {e}"
