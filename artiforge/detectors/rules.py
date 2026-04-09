"""Built-in detection rules for ArtiForge labs.

Each DetectionRule has:
  id        — short identifier, e.g. "DR-001"
  name      — human-readable description
  technique — MITRE ATT&CK technique ID
  check(bundle) — returns a list of GeneratedEvents that caused the rule to fire

Rules operate only on *attack* events (phase_id != 0).
Noise events (phase_id == 0) are excluded to avoid false positives from background traffic.

Add new rules by appending to RULES. The check command picks them up automatically.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from artiforge.core.models import ArtifactBundle, GeneratedEvent


def _attack(bundle: ArtifactBundle) -> list[GeneratedEvent]:
    """Return only attack events (exclude noise)."""
    return [e for e in bundle.events if e.phase_id != 0]


@dataclass
class DetectionRule:
    id: str
    name: str
    technique: str
    check: Callable[[ArtifactBundle], list[GeneratedEvent]]


# ── Trusted domains used in DR-005 ────────────────────────────────────────────

_TRUSTED_DOMAINS = (
    ".microsoft.com",
    ".windows.com",
    ".windowsupdate.com",
    ".office.com",
    ".office365.com",
    ".google.com",
    ".googleapis.com",
    ".gstatic.com",
    ".digicert.com",
    ".verisign.com",
)

# ── LOLBins matched in DR-001 ──────────────────────────────────────────────────

_LOLBINS = (
    "ie4uinit.exe",
    "msxsl.exe",
    "mshta.exe",
    "regsvr32.exe",
    "certutil.exe",
    "wmic.exe",
    "cscript.exe",
    "wscript.exe",
    "rundll32.exe",
    "installutil.exe",
    "msiexec.exe",
    "odbcconf.exe",
    "xwizard.exe",
)

# ── Suspicious file paths used in DR-009 ──────────────────────────────────────

_SUSPICIOUS_PATHS = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "\\public\\",
    "%temp%",
    "%appdata%",
)


# ── Rule definitions ───────────────────────────────────────────────────────────

RULES: list[DetectionRule] = [

    DetectionRule(
        id="DR-001",
        name="Suspicious LOLBin Execution",
        technique="T1218",
        check=lambda bundle: [
            e for e in _attack(bundle)
            if e.eid == 1 and e.channel == "Sysmon"
            and any(lb in e.event_data.get("Image", "").lower() for lb in _LOLBINS)
        ],
    ),

    DetectionRule(
        id="DR-002",
        name="Scheduled Task Creation via Event Log",
        technique="T1053.005",
        check=lambda bundle: [
            e for e in _attack(bundle) if e.eid == 4698
        ],
    ),

    DetectionRule(
        id="DR-003",
        name="Service Installation",
        technique="T1543.003",
        check=lambda bundle: [
            e for e in _attack(bundle) if e.eid == 7045
        ],
    ),

    DetectionRule(
        id="DR-004",
        name="Outbound Connection on Non-Standard Port",
        technique="T1071",
        check=lambda bundle: [
            e for e in _attack(bundle)
            if e.eid == 3 and e.channel == "Sysmon"
            and e.event_data.get("DestinationPort", "") not in ("80", "443", "53", "0", "")
        ],
    ),

    DetectionRule(
        id="DR-005",
        name="Suspicious DNS Query",
        technique="T1071.004",
        check=lambda bundle: [
            e for e in _attack(bundle)
            if e.eid == 22 and e.channel == "Sysmon"
            and not any(
                e.event_data.get("QueryName", "").lower().endswith(d)
                for d in _TRUSTED_DOMAINS
            )
        ],
    ),

    DetectionRule(
        id="DR-006",
        name="Logon Using Explicit Credentials",
        technique="T1078",
        check=lambda bundle: [
            e for e in _attack(bundle) if e.eid == 4648
        ],
    ),

    DetectionRule(
        id="DR-007",
        name="Registry Value Modified (Sysmon)",
        technique="T1112",
        check=lambda bundle: [
            e for e in _attack(bundle)
            if e.eid == 13 and e.channel == "Sysmon"
        ],
    ),

    DetectionRule(
        id="DR-008",
        name="New Local Account Created",
        technique="T1136.001",
        check=lambda bundle: [
            e for e in _attack(bundle) if e.eid == 4720
        ],
    ),

    DetectionRule(
        id="DR-009",
        name="File Created in Suspicious Path",
        technique="T1105",
        check=lambda bundle: [
            e for e in _attack(bundle)
            if e.eid == 11 and e.channel == "Sysmon"
            and any(
                p in e.event_data.get("TargetFilename", "").lower()
                for p in _SUSPICIOUS_PATHS
            )
        ],
    ),

    DetectionRule(
        id="DR-010",
        name="Remote Thread Injection",
        technique="T1055.003",
        check=lambda bundle: [
            e for e in _attack(bundle)
            if e.eid == 8 and e.channel == "Sysmon"
        ],
    ),

    DetectionRule(
        id="DR-011",
        name="LSASS Memory Access",
        technique="T1003.001",
        check=lambda bundle: [
            e for e in _attack(bundle)
            if e.eid == 10 and e.channel == "Sysmon"
            and "lsass" in e.event_data.get("TargetImage", "").lower()
        ],
    ),

    DetectionRule(
        id="DR-012",
        name="PowerShell Script Block Logged",
        technique="T1059.001",
        check=lambda bundle: [
            e for e in _attack(bundle)
            if e.eid == 4104 and e.channel == "PowerShell"
        ],
    ),

    DetectionRule(
        id="DR-013",
        name="WMI Subscription Created",
        technique="T1546.003",
        check=lambda bundle: [
            e for e in _attack(bundle)
            if e.eid == 5861 and e.channel == "WMI"
        ],
    ),
]


# ── Runner ─────────────────────────────────────────────────────────────────────

def run_rules(
    bundle: ArtifactBundle,
    rules: list[DetectionRule] | None = None,
) -> list[dict]:
    """Run all (or a subset of) rules against a bundle.

    Returns a list of result dicts, one per rule:
      {rule, fired: bool, matches: list[GeneratedEvent]}
    """
    active = rules if rules is not None else RULES
    results = []
    for rule in active:
        matches = rule.check(bundle)
        results.append({"rule": rule, "fired": bool(matches), "matches": matches})
    return results
