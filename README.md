# vector

A sequential, YAML-driven recon/enumeration pipeline whose goal is not
"list what's running" but **find where this host actually gives an
attacker a way in**. An nmap scan (TCP + a UDP sweep) seeds a knowledge
base with discovered ports/services; a controller then dispatches the
right tool modules per service (defined declaratively in YAML, no code
changes needed to add new triggers), storing every result as a
normalized "fact" in SQLite. At the end, every finding and credential
across the whole run is aggregated into a ranked, scored **entry-point
assessment** — the first thing you read in the report, not the last —
plus the full per-port detail and a `report.json`/`report.md` per
target.

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

- `nmap` (seed module — TCP + UDP port/service discovery, **and** the
  engine behind every `nse-probe`-based module below — most of this
  project's "sophistication" is nmap's own NSE script library, wrapped
  generically rather than reimplemented per protocol)
- `whatweb`, `nuclei`, `feroxbuster` (HTTP module)
- `enum4linux-ng`, `smbclient` (SMB module)
- `searchsploit` (CVE module — part of the `exploitdb` package:
  `apt install exploitdb` on Kali/Debian)
- `openssl` (TLS audit module)
- `hydra` (default-credential module)

`ssh-banner` and `ftp-anon-check` need no external binaries — they use
raw sockets directly. The CVE module's second source (NVD) needs no
binary either — it's a plain HTTPS call — but does need internet
egress to `services.nvd.nist.gov`; see below.

If a tool isn't installed, the framework doesn't crash: the registry
logs that the tool is unimplemented/unavailable for that trigger and
moves on. (Currently "unimplemented" means "no Python wrapper class
registered" — see below to add one; a future improvement would be to
also check `shutil.which()` and skip missing binaries at runtime.)

## Architecture

```
main.py
  └─> Controller (core/controller.py)
        ├─> runs seed module (nmap, TCP+UDP) per target -> port facts
        ├─> Registry (core/registry.py) loads modules/*.yaml
        │     and matches port/service facts to applicable tools
        ├─> runs each applicable Module (modules_impl/*.py) sequentially
        └─> stores all results in KnowledgeBase (core/knowledge_base.py, SQLite)
  └─> ReportGenerator (core/report.py)
        ├─> score_host() (core/scorer.py) -> ranked entry-point assessment
        └─> writes report.json / report.md (assessment first, detail after)
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

### Module inventory

| modules/*.yaml     | Trigger                      | Tool(s)              | What it's looking for |
|---------------------|-------------------------------|-----------------------|------------------------|
| `http.yaml`         | service: http/https/...       | whatweb, nuclei, feroxbuster | tech stack, live CVE matches, hidden paths |
| `smb.yaml`          | service: smb/...               | enum4linux-ng, smbclient | shares, null-session enum |
| `ssh.yaml`          | service: ssh                   | ssh-banner           | banner / version leak |
| `ftp.yaml`          | service: ftp                   | ftp-anon-check       | anonymous login |
| `redis.yaml`        | service: redis                 | nse-probe (redis-info) | no-auth-by-default |
| `mongodb.yaml`      | service: mongodb               | nse-probe            | no-auth, db enumeration |
| `mssql.yaml`        | service: ms-sql-s              | nse-probe            | blank `sa` password |
| `rdp.yaml`          | service: ms-wbt-server         | nse-probe            | weak encryption / no NLA |
| `vnc.yaml`          | service: vnc                   | nse-probe            | no auth, RealVNC auth-bypass |
| `nfs.yaml`          | service: nfs/rpcbind           | nse-probe            | world-mountable exports |
| `snmp.yaml`         | service: snmp (**UDP**)        | nse-probe            | guessable community strings |
| `mail.yaml`         | service: smtp/pop3/imap/...   | nse-probe            | open relay, banner leaks |
| `docker.yaml`       | **port:** 2375/2376            | nse-probe            | unauthenticated Docker Engine API |
| `elasticsearch.yaml`| **port:** 9200/9300            | nse-probe            | unauthenticated cluster API |
| `tls.yaml`          | **tunnel:** ssl                | tls-audit            | expired/self-signed certs, weak TLS |
| `cve.yaml`          | has_version: true               | searchsploit (+NVD)  | known CVEs for the fingerprint |
| `default-creds.yaml`| service: ssh/ftp/mysql/...    | hydra-default-creds  | factory/default credentials |

### Trigger kinds (modules/*.yaml)

- `service: [list]` — dispatch when the port fact's `service` name
  matches (http.yaml, smb.yaml, ssh.yaml, ftp.yaml, redis.yaml, ...).
- `has_version: true` — dispatch when the port fact has a non-empty
  `product` AND `version`, regardless of which service it is
  (cve.yaml).
- `port: [list]` — dispatch on the exact port number regardless of
  what nmap called the service. Used where nmap's service-name guess
  is unreliable on that port (docker.yaml, elasticsearch.yaml both
  often just get reported as generic "http").
- `tunnel: ssl` — dispatch on any port nmap flagged as SSL-wrapped,
  independent of the protocol running inside it (tls.yaml).

See `core/registry.py` → `ModuleDefinition.matches()` for all four.

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

### CVE lookup module (modules_impl/cve_lookup_module.py)

Triggers on `has_version: true` (modules/cve.yaml), so it runs against
**any** port nmap fingerprinted with a product and version string, not
just a specific protocol. Two sources, both best-effort:

1. **searchsploit (exploitdb)** — offline, local database. Needs the
   `exploitdb` apt package installed.
2. **NVD REST API** — online keyword search against the full CVE
   corpus. Set `NVD_API_KEY` in the environment to raise the request
   rate limit (free key from nvd.nist.gov); the module self-throttles
   to stay under the anonymous 5 req/30s limit either way. If NVD is
   unreachable (airgapped assessment, egress filtering) this source is
   skipped and you still get the exploitdb results.

**Both sources are keyword matches against `"<product> <version>"`,
not CPE version-range confirmed.** A hit is a lead to triage — check
the advisory, confirm the version range, confirm reachability — not a
validated finding. That's why these facts carry `"verified": false`
(except exploitdb entries exploitdb itself marks verified). Contrast
with nuclei's findings, which are live confirmed matches against the
real target. See the module's own docstring for the full caveat and
for a note on verifying the `searchsploit --json` field names against
your installed exploitdb version.

### Generic NSE-script probe (modules_impl/nse_probe_module.py)

Wraps nmap's own script engine generically instead of hand-rolling a
protocol client per service. A YAML module def that registers the
`nse-probe` tool supplies a custom `nse_scripts:` list (and optionally
`nse_script_args:`); the module reads it via `self.config` (every
module now gets its full parsed YAML dict, not just triggers/tools —
see `core/module_base.py`), runs `nmap --script <list> -p <port>`, and
turns each script's output into a `finding`. This is what backs
redis/mongodb/mssql/rdp/vnc/nfs/snmp/mail/docker/elasticsearch above —
ten modules, one implementation. A keyword scan over each script's
free-text output (`anonymous`, `VULNERABLE`, `open relay`, `NULL
session`, ...) flags the output as `severity: high` when one of those
phrases appears, else `info` — a heuristic, not a structured parser;
see the module docstring for the trade-off and when to graduate a
specific script to its own dedicated parser instead.

### TLS/SSL audit (modules_impl/tls_audit_module.py)

Fires on **any** TLS-wrapped port (the `tunnel: ssl` trigger), not
just 443/8443. Pulls certificate subject/issuer/validity via `openssl
x509` (deliberately not Python's stdlib `ssl.getpeercert()`, which
only parses a cert that already passed verification — exactly the
untrusted/self-signed/expired certs this module wants to see), flags
expired and self-signed certificates, and separately probes whether
the server still accepts TLS 1.0/1.1 (deprecated per RFC 8996). This
is a quick signal, not a full cipher-suite sweep — pair it with
testssl.sh/sslscan for that if installed.

### Default-credential check (modules_impl/default_creds_module.py)

Runs `hydra` with a short, built-in list (~4 users × 6 passwords —
`admin`/`admin`, `root`/`root`, blank password, etc.), **not** a large
wordlist, stopping at the first hit per service (`-f`) and capped at 4
threads. This is a "did anyone change the factory password" check, not
a brute-force tool — see the module docstring before extending the
credential list. **Only run against hosts you are authorized to
test**: repeated auth attempts are a real operational side effect
(account lockouts, SOC alerts), not a theoretical one.

### Entry-point assessment / scoring (core/scorer.py)

Every module above answers a narrow question. This answers the one an
operator actually opens the report for: *out of everything found,
where does this host give way first?* Pure aggregation, no network
calls — it runs once per host over the facts already in the knowledge
base and produces a ranked list plus an overall score/tier:

| Fact                          | Points |
|--------------------------------|--------|
| any `credential` fact          | 30     |
| `finding`, severity=critical   | 25     |
| `finding`, severity=high       | 15     |
| `finding`, severity=medium     | 8      |
| `finding`, severity=low        | 3      |
| severity=info/unknown          | 0 (context, not scored) |

Scores bucket into `CRITICAL` (≥50) / `HIGH` (≥25) / `MEDIUM` (≥10) /
`LOW` (≥1) / `MINIMAL` (0). Deliberately simple and auditable — every
point is traceable back to one fact already in `report.json`, and it
deliberately double-counts (five independent medium findings outrank
one, because five weak points is a bigger surface than one). It's a
triage ranking to decide where to spend manual validation time first,
**not** a CVSS-equivalent severity rating for a client-facing report.
`report.md`/`report.json` now lead with this section rather than
burying it after the per-port detail.

### Idempotency / resumability

`KnowledgeBase.modules_run` tracks per-host status, keyed on
`"<tool_name>@<port>"` for port-dispatched modules (or just
`<tool_name>` for the portless nmap seed module). Modules already
marked `success` for that key are skipped on the next run unless
`--force` is passed. Re-running an interrupted or partially-failed
target only re-executes what didn't finish (or failed) last time.

(Earlier builds of this pipeline keyed resumability on tool name alone,
which meant a tool matching two ports on the same host — whatweb on
:80 and :8080, or searchsploit against both an SSH and an HTTP
fingerprint — only ever ran once and silently skipped every port after
the first. Fixed as part of the per-port dispatch logic in
`core/controller.py`.)

## Not yet implemented

- **Exploiter stage** — intentionally out of scope for this build.
  When you're ready, it slots in the same way as any other module: a
  YAML file triggering on `finding: exploitdb_match` (or a specific
  `cve`) plus a wrapper that shells out to an existing tool (nuclei's
  exploit templates, `msfconsole` scripting, etc.) rather than
  generating exploit code directly.
- Concurrent/async execution (current design is intentionally sequential)
- Runtime binary-availability checks (`shutil.which`) before dispatch
- CPE-based version-range matching for the CVE module (currently
  keyword search only — see the caveat above)
- Dedicated structured parsers for specific high-value NSE scripts
  (currently all `nse-probe` output is the script's raw text plus a
  keyword-based severity heuristic — see the module's docstring for
  when a script's output earns its own parser instead)
- A full TLS cipher-suite sweep (tls-audit is a quick cert/protocol
  signal, deliberately not a testssl.sh/sslyze replacement)
- Per-host scoring only; no cross-host rollup (e.g. "3 of 40 hosts are
  CRITICAL") — would be a small addition to main.py's report loop once
  there's a report *set*, not just a report per host
