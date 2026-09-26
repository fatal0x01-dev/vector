# vector

A sequential, YAML-driven recon/enumeration pipeline. An nmap scan seeds
a knowledge base with discovered ports/services; a controller then
dispatches the right tool modules per service (defined declaratively in
YAML, no code changes needed to add new triggers), storing every result
as a normalized "fact" in SQLite. A report (JSON + Markdown) is
generated per target at the end.

## Quick start

```bash
pip install -r requirements.txt

# Single target
python3 main.py --target 10.0.0.5

# Target list (supports CIDR expansion)
python3 main.py --targets config/targets.yaml

# Force re-run even if modules already completed for this target
python3 main.py --target 10.0.0.5 --force
```

Output per target lands in `output/<host>/`:
- `knowledge.db` — SQLite knowledge base (facts + module run status)
- `<tool>_<timestamp>.log` — raw stdout/stderr per tool invocation
- `report.json` — full fact dump, machine-readable
- `report.md` — human-readable summary grouped by port/service

## Requirements

This framework wraps external recon tools via subprocess. To actually
produce results (not just skip gracefully) you'll need these installed
and on `$PATH`:

- `nmap` (seed module — port/service discovery)
- `whatweb`, `nuclei`, `feroxbuster` (HTTP module)
- `enum4linux-ng`, `smbclient` (SMB module)

`ssh-banner` and `ftp-anon-check` need no external binaries — they use
raw sockets directly.

If a tool isn't installed, the framework doesn't crash: the registry
logs that the tool is unimplemented/unavailable for that trigger and
moves on. (Currently "unimplemented" means "no Python wrapper class
registered" — see below to add one; a future improvement would be to
also check `shutil.which()` and skip missing binaries at runtime.)

## Architecture

```
main.py
  └─> Controller (core/controller.py)
        ├─> runs seed module (nmap) per target -> port facts
        ├─> Registry (core/registry.py) loads modules/*.yaml
        │     and matches port/service facts to applicable tools
        ├─> runs each applicable Module (modules_impl/*.py) sequentially
        └─> stores all results in KnowledgeBase (core/knowledge_base.py, SQLite)
  └─> ReportGenerator (core/report.py) -> report.json / report.md
```

### Fact model

Every module produces facts in this envelope:

```json
{
  "type": "port | technology | finding | credential | directory | share",
  "host": "10.0.0.5",
  "source_tool": "whatweb",
  "timestamp": "2026-08-01T12:00:00Z",
  "data": { ... tool-specific payload ... }
}
```

### Adding a new module (e.g. LDAP)

1. **Write the YAML trigger definition** — `modules/ldap.yaml`:
   ```yaml
   module: ldap
   triggers:
     service:
       - ldap
       - ldaps
   tools:
     - ldapsearch
   produces:
     - finding
   ```

2. **Write the Python wrapper** — `modules_impl/ldapsearch_module.py`,
   subclassing `Module` (see `core/module_base.py`) and implementing
   `applicable()`, `build_command()`, `parse_output()`. Decorate the
   class with `@register_implementation("ldapsearch")` so the name
   matches the `tools:` entry in the YAML.

3. **Import it** in `modules_impl/__init__.py` so the decorator fires.

No changes to `controller.py` or `registry.py` are needed — the
dispatch loop already asks "what's applicable?" generically.

### Idempotency / resumability

`KnowledgeBase.modules_run` tracks per-host, per-module status. Modules
already marked `success` are skipped on the next run unless `--force`
is passed. Re-running an interrupted or partially-failed target only
re-executes what didn't finish (or failed) last time.

## Not yet implemented

- **Exploiter stage** — intentionally out of scope for this build.
  When you're ready, it slots in the same way as any other module:
  a YAML file with `triggers: finding_type: cve` (or similar) plus a
  wrapper that shells out to an existing tool (nuclei's exploit
  templates, searchsploit, msfconsole scripting, etc.) rather than
  generating exploit code directly.
- Concurrent/async execution (current design is intentionally sequential)
- Runtime binary-availability checks (`shutil.which`) before dispatch
