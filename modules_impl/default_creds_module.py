"""
Default-credential check module
=================================
Probably the single highest-value "entry point" check this project can
make: a service left on factory/default credentials is a direct,
unauthenticated path in, full stop -- no CVE needed. Wraps `hydra`
against a small, deliberately short, built-in list of extremely common
defaults (admin/admin, root/root, the blank-password case, etc.), NOT
a large wordlist. This is a targeted check for "did anyone change the
factory password", not a brute-force/credential-stuffing run:

  - `-f` (stop on first valid pair found for that service) -- this
    module answers yes/no per service, it doesn't enumerate every
    valid account.
  - `-t 4` (low task/thread count) -- avoids hammering the target or
    tripping an account-lockout policy sitting behind it.
  - The credential list below is intentionally tiny (~10 pairs). This
    is a sanity check for forgotten defaults, not a password-spraying
    tool, and is not the module to extend with a big rockyou-style list.

Dispatched via modules/default-creds.yaml's `service:` trigger across
ssh, ftp, mysql, telnet, vnc, and redis -- the protocols hydra ships a
module for out of the box and that commonly turn up with unrotated
defaults in the kind of lab/CTF environment this project targets. Each
is a separate hydra invocation (not one combined run) since hydra's
argument shape for "no username, password-only" services (redis, vnc)
differs from the user+password services.

Scope reminder: only run this against hosts you are authorized to
test. A lockout, alert, or service disruption from repeated auth
attempts is a real operational side effect, not a theoretical one --
this is exactly the kind of module to disable (drop its YAML trigger,
or don't install hydra) for a target where that risk isn't acceptable.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from core.module_base import Module, ModuleResult
from core.registry import register_implementation

# Small and deliberate -- see module docstring. Not all pairs make
# sense for every protocol; build_command() picks the right subset for
# username-taking vs. password-only protocols.
DEFAULT_USERS = ["admin", "root", "administrator", "user"]
DEFAULT_PASSWORDS = ["admin", "password", "root", "123456", "", "changeme"]

# Protocols hydra addresses by a password only, no username.
PASSWORD_ONLY_PROTOCOLS = {"redis", "vnc"}

# Maps our port-fact `service` string (from nmap -sV) to hydra's module
# name, where they differ.
SERVICE_TO_HYDRA = {
    "ssh": "ssh", "ftp": "ftp", "mysql": "mysql", "telnet": "telnet",
    "vnc": "vnc", "redis": "redis",
}

HYDRA_HIT_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>\S+)\]\s+host:\s+(?P<host>\S+)\s+"
    r"(?:login:\s+(?P<login>\S*)\s+)?password:\s+(?P<password>.*)$"
)


@register_implementation("hydra-default-creds")
class DefaultCredsModule(Module):
    name = "hydra-default-creds"
    default_fact_type = "credential"
    timeout_seconds = 120

    def applicable(self, service_fact: dict[str, Any]) -> bool:
        return service_fact.get("service", "").lower() in SERVICE_TO_HYDRA

    def build_command(self, target_ctx: dict[str, Any]) -> list[str]:
        # Written here for interface consistency; run() below actually
        # materializes the temp wordlist files this needs and calls it.
        host, port = target_ctx["host"], target_ctx["port"]
        service = SERVICE_TO_HYDRA.get(str(target_ctx.get("service", "")).lower(), "")
        return ["hydra", "-f", "-t", "4", "-s", str(port), host, service]

    def parse_output(self, raw_stdout: str, target_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []
        for line in raw_stdout.splitlines():
            match = HYDRA_HIT_RE.search(line)
            if not match:
                continue
            login = match.group("login") or ""
            password = match.group("password")
            facts.append({
                "type": "credential",
                "data": {
                    "port": target_ctx.get("port"),
                    "credential": {"username": login, "password": password},
                },
            })
            facts.append({
                "type": "finding",
                "data": {
                    "port": target_ctx.get("port"),
                    "finding": "default_credentials_accepted",
                    "severity": "critical",
                    "verified": True,
                    "service": target_ctx.get("service"),
                },
            })
        return facts

    def run(self, target_ctx: dict[str, Any]) -> ModuleResult:
        host = target_ctx["host"]
        service = SERVICE_TO_HYDRA.get(str(target_ctx.get("service", "")).lower())
        log_path = self._log_path(host)

        if service is None:
            return ModuleResult(module_name=self.name, host=host, success=True, facts=[])

        with tempfile.TemporaryDirectory(prefix="vector-hydra-") as tmp:
            pass_path = Path(tmp) / "passwords.txt"
            pass_path.write_text("\n".join(DEFAULT_PASSWORDS) + "\n")

            cmd = ["hydra", "-f", "-t", "4"]
            if service in PASSWORD_ONLY_PROTOCOLS:
                cmd += ["-P", str(pass_path)]
            else:
                user_path = Path(tmp) / "users.txt"
                user_path.write_text("\n".join(DEFAULT_USERS) + "\n")
                cmd += ["-L", str(user_path), "-P", str(pass_path)]
            cmd += ["-s", str(target_ctx["port"]), host, service]

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_seconds)
                self._write_log(log_path, cmd, proc.stdout, proc.stderr, proc.returncode)
                raw_facts = self.parse_output(proc.stdout, target_ctx)
                facts = [self._to_envelope(f, host) for f in raw_facts]
                return ModuleResult(module_name=self.name, host=host, success=True,
                                     facts=facts, log_path=str(log_path))
            except FileNotFoundError:
                return ModuleResult(module_name=self.name, host=host, success=False,
                                     error="hydra not found on $PATH -- install the 'hydra' package")
            except subprocess.TimeoutExpired:
                return ModuleResult(module_name=self.name, host=host, success=False,
                                     error=f"hydra timed out after {self.timeout_seconds}s")
            except Exception as e:  # noqa: BLE001
                return ModuleResult(module_name=self.name, host=host, success=False, error=str(e))
