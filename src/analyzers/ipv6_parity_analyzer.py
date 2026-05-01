"""
Spots IPv6 holes that IPv4 already covers.

Two checks:
1) The auto-seeded "Default allow LAN IPv6 to any" rule. It comes from
   src/etc/config.xml.sample in opnsense/core and stays enabled unless
   removed. With a global IPv6 prefix on LAN this opens every host.
2) IPv4 vs IPv6 parity per interface. Pass rules with ipprotocol=inet
   that have no inet6/inet46 sibling get flagged.

The findings include a ready-to-use addRule payload so the dashboard can
apply the fix with one POST to /api/firewall/filter/addRule.
"""
from dataclasses import dataclass, field


@dataclass
class IPv6Finding:
    severity: str
    rule_id: str
    rule_description: str
    issue: str
    reason: str
    solution: str
    rule_details: dict
    interface: str = ""
    opnsense_path: str = "Firewall > Rules"
    implementation_steps: list[str] = field(default_factory=list)
    suggested_rule: dict | None = None


_ANY_V6 = {"any", "", "::/0"}
_ANY_V4 = {"any", "", "0.0.0.0/0"}


def _interfaces_of(rule: dict) -> list[str]:
    """Return the list of interfaces a rule applies to."""
    cached = rule.get("interfaces")
    if isinstance(cached, list) and cached:
        return cached
    raw = str(rule.get("interface", "") or "")
    return [i for i in raw.split(",") if i]


def _rule_signature(rule: dict) -> tuple:
    """A coarse identity for parity matching across address families."""
    return (
        rule.get("action", ""),
        rule.get("direction", ""),
        rule.get("protocol", "") or "any",
        rule.get("source_net", "") or "any",
        rule.get("source_port", ""),
        rule.get("destination_net", "") or "any",
        rule.get("destination_port", ""),
    )


def _is_default_allow_lan_v6(rule: dict) -> bool:
    """Match the auto rule from config.xml.sample.

    Heuristic: enabled, action=pass, ipprotocol=inet6, interface contains
    'lan', source_net is the lan alias 'lan', destination_net is 'any',
    and there is no port restriction. Description hint is optional.
    """
    if str(rule.get("enabled", "0")) != "1":
        return False
    if rule.get("action") != "pass":
        return False
    if rule.get("ipprotocol") != "inet6":
        return False
    iface = str(rule.get("interface", "")).lower()
    if "lan" not in iface:
        return False
    src = str(rule.get("source_net", "")).lower()
    dst = str(rule.get("destination_net", "")).lower()
    if src not in {"lan", "lannet", "lan_net"}:
        return False
    if dst not in _ANY_V6 and dst != "any":
        return False
    if str(rule.get("destination_port", "")):
        return False
    return True


def _v6_pair_for(rule: dict, by_iface_v6: dict[str, list[dict]]) -> dict | None:
    sig = _rule_signature(rule)
    for iface in _interfaces_of(rule):
        for cand in by_iface_v6.get(iface, []):
            if _rule_signature(cand) == sig:
                return cand
    return None


def _suggest_block_for(rule: dict) -> dict:
    """Return an addRule payload that blocks v6 inbound to host until reviewed."""
    interfaces = _interfaces_of(rule) or ["wan"]
    return {
        "rule": {
            "enabled": "1",
            "action": "block",
            "direction": "in",
            "ipprotocol": "inet6",
            "protocol": "any",
            "interface": ",".join(interfaces),
            "source_net": "any",
            "destination_net": "any",
            "log": "1",
            "quick": "1",
            "description": "secops: block v6 ingress until reviewed",
        }
    }


def _suggest_v6_mirror(rule: dict) -> dict:
    """Mirror an inet rule onto inet6 with the same selectors."""
    interfaces = _interfaces_of(rule) or [""]
    return {
        "rule": {
            "enabled": "1",
            "action": rule.get("action", "pass"),
            "direction": rule.get("direction", "in"),
            "ipprotocol": "inet6",
            "protocol": rule.get("protocol", "any"),
            "interface": ",".join(interfaces),
            "source_net": rule.get("source_net", "any"),
            "source_port": rule.get("source_port", ""),
            "destination_net": rule.get("destination_net", "any"),
            "destination_port": rule.get("destination_port", ""),
            "log": rule.get("log", "0"),
            "quick": rule.get("quick", "1"),
            "description": f"secops: v6 sibling of {rule.get('description', rule.get('uuid', ''))[:80]}",
        }
    }


class IPv6ParityAnalyzer:
    """Run all IPv6 parity checks and return findings."""

    def __init__(self, exceptions: list[dict] | None = None, strict: bool = True) -> None:
        self.exceptions = exceptions or []
        self.strict = strict
        self._exempt_uuids = {e.get("rule_id") for e in self.exceptions if e.get("rule_id")}

    def analyze(self, firewall_rules: list[dict], interfaces_info: list[dict] | None = None) -> list[IPv6Finding]:
        findings: list[IPv6Finding] = []
        if not firewall_rules:
            return findings

        # Map identifier (lan, opt5, ...) to whether the interface has a global v6 address.
        v6_active_ifaces: set[str] = set()
        for row in interfaces_info or []:
            ident = (row.get("identifier") or "").lower()
            addr6 = (row.get("addr6") or "")
            if not ident or not addr6:
                continue
            if addr6.startswith(("fe80", "::1", "fd")):
                # link-local, loopback or ULA only does not count as exposure
                continue
            v6_active_ifaces.add(ident)

        for rule in firewall_rules:
            uuid = rule.get("uuid", "")
            if uuid in self._exempt_uuids:
                continue
            if _is_default_allow_lan_v6(rule):
                findings.append(self._auto_lan_finding(rule))

        v6_by_iface: dict[str, list[dict]] = {}
        for rule in firewall_rules:
            if str(rule.get("enabled", "0")) != "1":
                continue
            if rule.get("ipprotocol") not in ("inet6", "inet46"):
                continue
            for iface in _interfaces_of(rule):
                v6_by_iface.setdefault(iface, []).append(rule)

        for rule in firewall_rules:
            if str(rule.get("enabled", "0")) != "1":
                continue
            if rule.get("action") != "pass":
                continue
            if rule.get("ipprotocol") != "inet":
                continue
            if rule.get("uuid") in self._exempt_uuids:
                continue
            if _v6_pair_for(rule, v6_by_iface):
                continue
            ifaces = _interfaces_of(rule)
            iface_has_v6 = any(i in v6_active_ifaces for i in ifaces)
            findings.append(self._parity_finding(rule, iface_has_v6))

        return findings

    def _auto_lan_finding(self, rule: dict) -> IPv6Finding:
        sev = "CRITICAL" if self.strict else "HIGH"
        iface = (_interfaces_of(rule) or ["lan"])[0]
        return IPv6Finding(
            severity=sev,
            rule_id=rule.get("uuid", "auto_lan_v6"),
            rule_description=rule.get("description", "Default allow LAN IPv6 to any rule"),
            issue="Auto-Regel 'Default allow LAN IPv6 to any' aktiv",
            reason=(
                "Diese Auto-Regel kommt aus config.xml.sample und passt jeden "
                "ausgehenden IPv6 Verkehr aus LAN durch. Mit globalem IPv6 Praefix "
                "haben alle LAN Hosts eine direkt routbare Adresse. Es gibt kein NAT, "
                "das den Eingang stoppt. Verbindungen aus dem Internet zum globalen "
                "Praefix landen nur dann nicht beim Host, wenn eine separate Block "
                "Regel auf WAN greift."
            ),
            solution=(
                "Regel begrenzen auf die wirklich noetigen Ports und Ziele oder "
                "ersetzen durch eine inet46 Pass Regel mit Alias fuer DNS, NTP, HTTPS, "
                "oder direkt loeschen wenn IPv6 aus LAN nicht raus soll."
            ),
            rule_details=rule,
            interface=iface,
            opnsense_path="Firewall > Rules > LAN",
            implementation_steps=[
                "1. Firewall > Rules > LAN oeffnen.",
                f"2. Regel '{rule.get('description', 'Default allow LAN IPv6 to any rule')}' suchen.",
                "3. Action auf Block setzen, oder Regel deaktivieren, oder Source/Destination einschraenken.",
                "4. Speichern und Apply Changes.",
            ],
            suggested_rule={
                "rule": {
                    "enabled": "0",
                    "action": rule.get("action", "pass"),
                    "direction": rule.get("direction", "in"),
                    "ipprotocol": "inet6",
                    "protocol": "any",
                    "interface": rule.get("interface", iface),
                    "source_net": rule.get("source_net", "lan"),
                    "destination_net": rule.get("destination_net", "any"),
                    "log": "1",
                    "quick": "1",
                    "description": (rule.get("description") or "Default allow LAN IPv6 to any rule") + " (deaktiviert durch secops)",
                }
            },
        )

    def _parity_finding(self, rule: dict, iface_has_v6: bool) -> IPv6Finding:
        if iface_has_v6:
            sev = "CRITICAL" if self.strict else "HIGH"
        else:
            sev = "LOW"
        iface = (_interfaces_of(rule) or ["floating"])[0]
        desc = rule.get("description") or rule.get("uuid", "rule")
        return IPv6Finding(
            severity=sev,
            rule_id=rule.get("uuid", ""),
            rule_description=desc,
            issue="IPv4 Pass Regel ohne IPv6 Pendant",
            reason=(
                "Auf Interface " + iface + " gibt es eine inet Pass Regel ohne "
                "inet6 oder inet46 Sibling mit gleichen Selektoren. Wenn das "
                "Interface IPv6 spricht oder spaeter bekommt, faellt die Pass "
                "Logik auf der v6 Seite weg oder die Default Allow Auto Regel "
                "uebernimmt. Beides ist nicht gewollt."
            ),
            solution=(
                "Eine inet6 Sibling Regel anlegen, oder die Originalregel auf "
                "inet46 umstellen wenn Source und Destination Aliase beide "
                "Familien koennen."
            ),
            rule_details=rule,
            interface=iface,
            opnsense_path="Firewall > Rules > " + iface.upper(),
            implementation_steps=[
                "1. Firewall > Rules > " + iface.upper() + " oeffnen.",
                "2. Regel duplizieren.",
                "3. ipprotocol auf inet6 setzen.",
                "4. Speichern, Apply Changes.",
                "5. Alternativ: Originalregel auf inet46 setzen.",
            ],
            suggested_rule=_suggest_v6_mirror(rule),
        )
