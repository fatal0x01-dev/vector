"""
Entry-point scorer
===================
Every module in this project answers a narrow question ("is this port
open", "does this service take default creds", "is this CVE
plausible", "is this cert expired"). None of them answer the actual
question an operator opens the report to ask: *out of everything we
just found, where does this host actually give way first?*

This module is pure aggregation over facts already in the knowledge
base -- it runs no tools, touches no network, and adds no new fact
type. It's called once per host after the dispatch loop finishes (see
ReportGenerator in core/report.py, which calls score_host() and
renders its output as the first section of report.md/report.json --
intentionally first, since it's the answer, and the per-port/per-tool
detail further down is the supporting evidence).

Scoring model
-------------
Deliberately simple and auditable over "sophisticated": every `finding`
and `credential` fact contributes points by severity; nothing here is
a black box an operator can't recompute by hand from the fact list.

    credential fact (any)                      +30
    finding, severity=critical                 +25
    finding, severity=high                      +15
    finding, severity=medium                     +8
    finding, severity=low                        +3
    finding, severity=info/unknown                0  (context, not exposure)

Points are summed per host, then bucketed into a tier:

    >= 50   CRITICAL   -- unauthenticated access or a confirmed default
                          credential puts this host's compromise at
                          "when", not "if"
    25-49   HIGH        -- a serious, specific weakness (exploitable
                          CVE match, open relay, anonymous SMB/FTP)
    10-24   MEDIUM      -- real but second-order issues (weak TLS,
                          expired/self-signed cert, minor info leak)
    1-9     LOW         -- informational findings with minor severity
    0       MINIMAL     -- nothing scored; doesn't mean "secure", means
                          "nothing this pipeline's modules flagged"

This is a triage ranking, not a vulnerability-management score (it
isn't CVSS, doesn't account for exploit maturity or network position,
and double-counts deliberately -- five separate medium findings on one
host SHOULD outrank one medium finding, because five independent weak
points is a bigger attack surface than one). Use it to decide where to
spend manual validation time first, not as a final severity rating in
a client-facing report.
"""

from __future__ import annotations

from typing import Any

SEVERITY_POINTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
    "unknown": 0,
}

CREDENTIAL_POINTS = 30

TIER_THRESHOLDS = [
    (50, "CRITICAL"),
    (25, "HIGH"),
    (10, "MEDIUM"),
    (1, "LOW"),
    (0, "MINIMAL"),
]


def _tier_for(score: int) -> str:
    for threshold, tier in TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return "MINIMAL"


def _label_for_finding(data: dict[str, Any]) -> str:
    label = data.get("finding") or data.get("cve") or "finding"
    cve = data.get("cve")
    if cve and cve != label:
        label = f"{label} [{cve}]"
    return label


def score_host(facts: list[dict[str, Any]]) -> dict[str, Any]:
    """
    facts: the full fact list for one host, as returned by
    KnowledgeBase.get_facts(host=...) -- same input report.py already
    has on hand when it builds the rest of the report.

    Returns:
        {
            "score": int,
            "tier": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "MINIMAL",
            "entry_points": [
                {"label": str, "port": int|None, "severity": str,
                 "points": int, "source_tool": str, "type": "finding"|"credential"},
                ...
            ],  # sorted by points desc, highest-value entries first
            "breakdown": {"critical": n, "high": n, "medium": n, "low": n, "credentials": n},
        }
    """
    entry_points: list[dict[str, Any]] = []
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "credentials": 0}

    for fact in facts:
        if fact["type"] == "credential":
            cred = fact["data"].get("credential", {})
            label = f"credential: {cred.get('username', '')}/{cred.get('password', '')}"
            entry_points.append({
                "label": label, "port": fact["data"].get("port"),
                "severity": "critical", "points": CREDENTIAL_POINTS,
                "source_tool": fact["source_tool"], "type": "credential",
            })
            breakdown["credentials"] += 1

        elif fact["type"] == "finding":
            severity = str(fact["data"].get("severity", "unknown")).lower()
            points = SEVERITY_POINTS.get(severity, 0)
            if points <= 0:
                continue  # informational -- not an entry point, skip
            entry_points.append({
                "label": _label_for_finding(fact["data"]), "port": fact["data"].get("port"),
                "severity": severity, "points": points,
                "source_tool": fact["source_tool"], "type": "finding",
            })
            if severity in breakdown:
                breakdown[severity] += 1

    entry_points.sort(key=lambda e: e["points"], reverse=True)
    score = sum(e["points"] for e in entry_points)

    return {
        "score": score,
        "tier": _tier_for(score),
        "entry_points": entry_points,
        "breakdown": breakdown,
    }
