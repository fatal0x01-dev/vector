"""
Registry
========
Loads module definitions (YAML) from the `modules/` directory, e.g.:

    module: http
    triggers:
      service:
        - http
        - https
    tools:
      - httpx
      - whatweb
      - nuclei
      - feroxbuster
    produces:
      - webserver
      - technologies
      - directories

Each `tools` entry maps to a concrete Module subclass registered in
MODULE_IMPLEMENTATIONS (in modules_impl/). The registry's job is purely
"given a service fact, which module instances are applicable?" -- it
knows nothing about how to execute them.

Adding a new module = drop a new YAML file + a new Module subclass +
one line in MODULE_IMPLEMENTATIONS. No controller changes required.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from core.module_base import Module

# Maps a "tool" name referenced in YAML to its concrete implementation class.
# Populated by importing modules_impl and registering classes there, or
# filled in directly here as modules are implemented.
MODULE_IMPLEMENTATIONS: dict[str, type[Module]] = {}


def register_implementation(tool_name: str):
    """Decorator: register a Module subclass under a tool name used in YAML."""
    def _wrap(cls: type[Module]):
        MODULE_IMPLEMENTATIONS[tool_name] = cls
        return cls
    return _wrap


class ModuleDefinition:
    """Parsed representation of one modules/*.yaml file."""

    def __init__(self, raw: dict[str, Any]):
        self.name: str = raw["module"]
        self.triggers: dict[str, Any] = raw.get("triggers", {})
        self.tool_names: list[str] = raw.get("tools", [])
        self.produces: list[str] = raw.get("produces", [])
        self.raw = raw

    def matches(self, service_fact: dict[str, Any]) -> bool:
        """
        Does this module's trigger config match a given service fact?
        service_fact looks like {"port": 445, "service": "smb"} (the
        `data` payload of a `type: port` or `type: service` fact).
        Matching is currently service-name based; extendable to
        port-based or regex-based triggers later.
        """
        trigger_services = [s.lower() for s in self.triggers.get("service", [])]
        fact_service = str(service_fact.get("service", "")).lower()
        return fact_service in trigger_services


class Registry:
    def __init__(self, modules_dir: str | Path, output_dir: str | Path):
        self.modules_dir = Path(modules_dir)
        self.output_dir = Path(output_dir)
        self.definitions: list[ModuleDefinition] = []
        self._load_definitions()

    def _load_definitions(self) -> None:
        for yaml_path in sorted(self.modules_dir.glob("*.yaml")):
            with open(yaml_path) as f:
                raw = yaml.safe_load(f)
            self.definitions.append(ModuleDefinition(raw))

    def applicable_modules(self, service_fact: dict[str, Any]) -> list[Module]:
        """
        Given a service fact's data payload (e.g. {"port": 80, "service": "http"}),
        return instantiated Module objects for every tool that should run.
        Tools without a registered implementation are skipped with a note
        (rather than crashing the whole run) so partial builds still work.
        """
        instances: list[Module] = []
        for definition in self.definitions:
            if not definition.matches(service_fact):
                continue
            for tool_name in definition.tool_names:
                impl_cls = MODULE_IMPLEMENTATIONS.get(tool_name)
                if impl_cls is None:
                    continue  # not implemented yet -- skip gracefully
                instance = impl_cls(output_dir=self.output_dir)
                instance.name = tool_name
                instance.triggers = definition.triggers
                instance.produces = definition.produces
                instances.append(instance)
        return instances

    def unimplemented_tools(self, service_fact: dict[str, Any]) -> list[str]:
        """Tool names referenced in matching YAML defs with no Python impl yet."""
        missing = []
        for definition in self.definitions:
            if not definition.matches(service_fact):
                continue
            for tool_name in definition.tool_names:
                if tool_name not in MODULE_IMPLEMENTATIONS:
                    missing.append(tool_name)
        return missing
