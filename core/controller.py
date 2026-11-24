"""
Controller
==========
Orchestrates the sequential recon pipeline per target:

    1. Run the seed module (nmap) to discover open ports/services.
    2. Store resulting `port` facts in the knowledge base.
    3. For each discovered service, ask the registry which modules
       are applicable and run them one at a time.
    4. Store every fact each module produces.
    5. Track module success/failure per host (and per port, see below)
       for resumability.

One Controller instance handles a target list; each target gets its
own knowledge base file and log directory under output/<host>/.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from core.knowledge_base import KnowledgeBase
from core.registry import Registry, MODULE_IMPLEMENTATIONS
from core.module_base import ModuleResult

logger = logging.getLogger("controller")


class Controller:
    def __init__(
        self,
        targets: list[str],
        modules_dir: str | Path = "modules",
        output_dir: str | Path = "output",
        force: bool = False,
    ):
        self.targets = targets
        self.output_dir = Path(output_dir)
        self.modules_dir = Path(modules_dir)
        self.force = force  # if True, re-run modules even if already marked success

        self.registry = Registry(modules_dir=self.modules_dir, output_dir=self.output_dir)

    def run(self) -> dict[str, KnowledgeBase]:
        """Run recon against every target. Returns {host: KnowledgeBase}."""
        kbs: dict[str, KnowledgeBase] = {}
        for host in self.targets:
            kbs[host] = self.run_target(host)
        return kbs

    def run_target(self, host: str) -> KnowledgeBase:
        target_output_dir = self.output_dir / host
        kb = KnowledgeBase(target_output_dir / "knowledge.db")

        logger.info("=== Starting recon for %s ===", host)

        self._run_seed_module(host, kb, target_output_dir)
        self._run_dispatch_loop(host, kb, target_output_dir)

        logger.info("=== Finished recon for %s ===", host)
        return kb

    # ------------------------------------------------------------------

    def _run_seed_module(self, host: str, kb: KnowledgeBase, target_output_dir: Path) -> None:
        seed_cls = MODULE_IMPLEMENTATIONS.get("nmap")
        if seed_cls is None:
            logger.warning("No seed module ('nmap') registered -- skipping port discovery")
            return

        module_name = "nmap"
        if kb.has_run(host, module_name) and not self.force:
            logger.info("[%s] %s already run -- skipping", host, module_name)
            return

        kb.mark_running(host, module_name)
        seed = seed_cls(output_dir=target_output_dir)
        seed.name = module_name

        result = seed.run({"host": host})
        self._store_result(kb, result)
        kb.mark_finished(host, module_name, result.success)

    def _run_dispatch_loop(self, host: str, kb: KnowledgeBase, target_output_dir: Path) -> None:
        port_facts = kb.get_facts(host=host, fact_type="port")

        for fact in port_facts:
            service_fact = fact["data"]  # {"port": 80, "service": "http", "product": ..., "version": ...}
            applicable = self.registry.applicable_modules(service_fact)

            missing = self.registry.unimplemented_tools(service_fact)
            for tool_name in missing:
                logger.info(
                    "[%s] port %s/%s matched module for '%s' but no implementation registered -- skipping",
                    host, service_fact.get("port"), service_fact.get("service"), tool_name,
                )

            for module in applicable:
                port = service_fact.get("port")
                target_ctx = {
                    "host": host,
                    "port": port,
                    "service": service_fact.get("service"),
                    "product": service_fact.get("product"),
                    "version": service_fact.get("version"),
                }

                # Resumability key is (module tool name, port) rather than
                # just the tool name. Without the port, a tool that legally
                # matches more than one port on the same host -- whatweb on
                # :80 and :8080, or searchsploit against both an SMB and an
                # HTTP fingerprint -- would run once for the first matching
                # port and then silently skip every later one, because
                # has_run()/mark_finished() only ever saw one (host, module)
                # pair. Keying on the port fixes that without touching the
                # KnowledgeBase schema; result.module_name (used for fact
                # source_tool and log file names) is untouched.
                run_key = f"{module.name}@{port}" if port is not None else module.name

                if kb.has_run(host, run_key) and not self.force:
                    logger.info("[%s] %s already run -- skipping", host, run_key)
                    continue

                logger.info(
                    "[%s] running %s (service=%s, port=%s)",
                    host, module.name, target_ctx["service"], port,
                )

                kb.mark_running(host, run_key)
                result = module.run(target_ctx)
                self._store_result(kb, result)
                kb.mark_finished(host, run_key, result.success)

    @staticmethod
    def _store_result(kb: KnowledgeBase, result: ModuleResult) -> None:
        if not result.success:
            logger.warning(
                "[%s] %s failed: %s", result.host, result.module_name, result.error
            )
            return
        if result.facts:
            kb.add_facts(result.facts)
            logger.info(
                "[%s] %s produced %d fact(s)", result.host, result.module_name, len(result.facts)
            )
