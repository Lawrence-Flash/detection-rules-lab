"""ATT&CK techniques this lab is willing to put on a rule.

Checked against MITRE ATT&CK enterprise v20 (October 2026). Tactic tags use
the current shortnames, including hyphens, for example attack.credential-access
and attack.stealth. v20 renamed Defense Evasion to Stealth and added Defense
Impairment. Clear Windows Event Logs is T1685.005. The old id T1070.001 is
revoked.

This file is a small allow-list, not a copy of the matrix. Add a technique
only after reading its current page.
"""

from __future__ import annotations

# Slug, display name. Order matches the enterprise tactic table.
TACTICS: tuple[tuple[str, str], ...] = (
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("stealth", "Stealth"),
    ("defense-impairment", "Defense Impairment"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
)

# technique id -> name, tactic slugs, canonical URL
TECHNIQUES: dict[str, dict[str, object]] = {
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactics": ("credential-access",),
        "url": "https://attack.mitre.org/techniques/T1003/001/",
    },
    "T1027.010": {
        "name": "Obfuscated Files or Information: Command Obfuscation",
        "tactics": ("stealth",),
        "url": "https://attack.mitre.org/techniques/T1027/010/",
    },
    "T1053.003": {
        "name": "Scheduled Task/Job: Cron",
        "tactics": ("execution", "persistence", "privilege-escalation"),
        "url": "https://attack.mitre.org/techniques/T1053/003/",
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactics": ("execution", "persistence", "privilege-escalation"),
        "url": "https://attack.mitre.org/techniques/T1053/005/",
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactics": ("execution",),
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1059.004": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactics": ("execution",),
        "url": "https://attack.mitre.org/techniques/T1059/004/",
    },
    "T1098.004": {
        "name": "Account Manipulation: SSH Authorized Keys",
        "tactics": ("persistence", "privilege-escalation"),
        "url": "https://attack.mitre.org/techniques/T1098/004/",
    },
    "T1098.007": {
        "name": "Account Manipulation: Additional Local or Domain Groups",
        "tactics": ("persistence", "privilege-escalation"),
        "url": "https://attack.mitre.org/techniques/T1098/007/",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactics": ("command-and-control",),
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactics": ("credential-access",),
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1136.001": {
        "name": "Create Account: Local Account",
        "tactics": ("persistence",),
        "url": "https://attack.mitre.org/techniques/T1136/001/",
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactics": ("stealth",),
        "url": "https://attack.mitre.org/techniques/T1140/",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactics": ("initial-access",),
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1548.003": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactics": ("privilege-escalation",),
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "T1550.002": {
        "name": "Use Alternate Authentication Material: Pass the Hash",
        "tactics": ("lateral-movement",),
        "url": "https://attack.mitre.org/techniques/T1550/002/",
    },
    "T1595.002": {
        "name": "Active Scanning: Vulnerability Scanning",
        "tactics": ("reconnaissance",),
        "url": "https://attack.mitre.org/techniques/T1595/002/",
    },
    "T1685.005": {
        "name": "Disable or Modify Tools: Clear Windows Event Logs",
        "tactics": ("defense-impairment",),
        "url": "https://attack.mitre.org/techniques/T1685/005/",
    },
}


def tactic_tag(slug: str) -> str:
    """Sigma tag for a tactic slug, for example attack.credential-access."""
    return "attack." + slug


def technique_tag(technique_id: str) -> str:
    """Sigma tag for a technique id, for example attack.t1110.001."""
    return "attack." + technique_id.lower()


def expected_tags(technique_ids: list[str]) -> set[str]:
    """Tactic tags plus technique tags required for this set of techniques."""
    tags: set[str] = set()
    tactics: set[str] = set()
    for technique_id in technique_ids:
        info = TECHNIQUES[technique_id]
        tags.add(technique_tag(technique_id))
        tactics.update(info["tactics"])  # type: ignore[arg-type]
    for slug in tactics:
        tags.add(tactic_tag(slug))
    return tags


def tactic_name(slug: str) -> str:
    for key, display in TACTICS:
        if key == slug:
            return display
    raise KeyError(slug)
