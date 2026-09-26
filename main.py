#!/usr/bin/env python3
"""
vector -- CLI entrypoint
=======================
Usage:
    python3 main.py --targets config/targets.yaml
    python3 main.py --target 10.0.0.5
    python3 main.py --target 10.0.0.5 --force        # re-run all modules
    python3 main.py --targets config/targets.yaml --output-dir output --modules-dir modules

Loads the target list, runs the sequential recon pipeline (nmap seed ->
service-based module dispatch) via Controller, then writes report.json
and report.md per target.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from pathlib import Path

import yaml

import modules_impl  # noqa: F401  -- triggers @register_implementation on import
from core.controller import Controller
from core.report import ReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("main")


def load_targets_from_yaml(path: str | Path) -> list[str]:
    with open(path) as f:
        config = yaml.safe_load(f)
    raw_targets = config.get("targets", [])
    return expand_targets(raw_targets)


def expand_targets(raw_targets: list[str]) -> list[str]:
    """Expand any CIDR ranges into individual host IPs; pass through hostnames/IPs as-is."""
    expanded: list[str] = []
    for entry in raw_targets:
        entry = str(entry).strip()
        if "/" in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                expanded.extend(str(ip) for ip in network.hosts())
                continue
            except ValueError:
                pass  # not a valid CIDR, fall through and treat as literal
        expanded.append(entry)
    return expanded


def main() -> int:
    parser = argparse.ArgumentParser(description="Sequential recon/enumeration pipeline")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--targets", help="Path to a targets YAML file")
    target_group.add_argument("--target", help="Single target host/IP")

    parser.add_argument("--modules-dir", default="modules", help="Directory of module YAML definitions")
    parser.add_argument("--output-dir", default="output", help="Directory for logs, knowledge DBs, reports")
    parser.add_argument("--force", action="store_true", help="Re-run modules even if already completed")
    args = parser.parse_args()

    if args.targets:
        targets = load_targets_from_yaml(args.targets)
    else:
        targets = expand_targets([args.target])

    if not targets:
        logger.error("No targets resolved -- check your targets file/argument.")
        return 1

    logger.info("Loaded %d target(s): %s", len(targets), ", ".join(targets))

    controller = Controller(
        targets=targets,
        modules_dir=args.modules_dir,
        output_dir=args.output_dir,
        force=args.force,
    )
    kbs = controller.run()

    logger.info("Generating reports...")
    for host, kb in kbs.items():
        target_output_dir = Path(args.output_dir) / host
        report_gen = ReportGenerator(kb, host, target_output_dir)
        json_path, md_path = report_gen.generate()
        logger.info("[%s] report written: %s , %s", host, json_path, md_path)
        kb.close()

    logger.info("Done. See %s/<host>/report.md for a summary of each target.", args.output_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
