"""
IPv6 hygiene checks for OPNsense.

Three checks:
1) Detect the auto-seeded "Default allow LAN IPv6 to any" rule. The rule itself
   only permits LAN clients to initiate outbound v6, return traffic is handled
   by the stateful filter. It does not, by itself, expose hosts to the internet.
   Finding fires when there is no explicit WAN inbound block to LAN net as
   defense in depth.
2) Audit WAN inbound IPv6 PASS rules. Each one is a potential exposure of an
   internal service over IPv6.
3) IPv4 vs IPv6 parity per interface, kept as LOW since a missing v6 pass
   rule is a feature gap, not a hole. Default-deny still blocks the traffic.

Findings carry an addRule payload so the dashboard can apply the fix with one
POST to /api/firewall/filter/addRule.
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
_LAN_NET_ALIASES = {"lan", "lannet", "lan_net"}


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
    """Match the auto rule shape from config.xml.sample."""
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
    if src not in _LAN_NET_ALIASES:
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


def _has_wan_v6_block_to_lan(rules: list[dict]) -> bool:
    """True when an explicit WAN inbound block to lan net for v6 already exists."""
    for r in rules:
        if str(r.get("enabled", "0")) != "1":
            continue
        if r.get("action") != "block":
            continue
        if r.get("direction") not in ("in", "any", ""):
            continue
        if r.get("ipprotocol") not in ("inet6", "inet46"):
            continue
        if not any("wan" in (i or "").lower() for i in _interfaces_of(r)):
            continue
        dst = str(r.get("destination_net", "")).lower()
        if dst in _LAN_NET_ALIASES:
            return True
    return False


def _suggest_wan_block_to_lan_v6() -> dict:
    """Defense in depth, explicit WAN inbound block of v6 to lan net."""
    return {
        "rule": {
            "enabled": "1",
            "action": "block",
            "direction": "in",
            "ipprotocol": "inet6",
            "protocol": "any",
            "interface": "wan",
            "source_net": "any",
            "destination_net": "lan",
            "log": "1",
            "quick": "1",
            "description": "secops: block inbound IPv6 to LAN net (defense in depth)",
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
    """Run all IPv6 checks and return findings."""

    def __init__(self, exceptions: list[dict] | None = None, strict: bool = True) -> None:
        self.exceptions = exceptions or []
        self.strict = strict
        self._exempt_uuids = {e.get("rule_id") for e in self.exceptions if e.get("rule_id")}

    def analyze(self, firewall_rules: list[dict], interfaces_info: list[dict] | None = None) -> list[IPv6Finding]:
        findings: list[IPv6Finding] = []
        if not firewall_rules:
            return findings

        v6_active_ifaces: set[str] = set()
        for row in interfaces_info or []:
            ident = (row.get("identifier") or "").lower()
            addr6 = (row.get("addr6") or "")
            if not ident or not addr6:
                continue
            if addr6.startswith(("fe80", "::1", "fd")):
                continue
            v6_active_ifaces.add(ident)

        wan_block_present = _has_wan_v6_block_to_lan(firewall_rules)

        for rule in firewall_rules:
            uuid = rule.get("uuid", "")
            if uuid in self._exempt_uuids:
                continue
            if _is_default_allow_lan_v6(rule):
                findings.append(self._auto_lan_finding(rule, wan_block_present))

        # WAN inbound v6 pass rules expose internal services. List them.
        for rule in firewall_rules:
            if str(rule.get("enabled", "0")) != "1":
                continue
            if rule.get("uuid") in self._exempt_uuids:
                continue
            if rule.get("action") != "pass":
                continue
            if rule.get("ipprotocol") not in ("inet6", "inet46"):
                continue
            if rule.get("direction") not in ("in", "any", ""):
                continue
            ifaces = _interfaces_of(rule)
            if not any("wan" in (i or "").lower() for i in ifaces):
                continue
            findings.append(self._wan_v6_pass_finding(rule))

        # Parity check, downgraded to LOW because default-deny already protects.
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

    def _auto_lan_finding(self, rule: dict, wan_block_present: bool) -> IPv6Finding:
        # Pure informational. The rule does not expose anything by itself.
        # Default deny on WAN is registered as inet46 in filter.lib.inc, the
        # explicit WAN block to LAN net is a defense in depth pattern, not a
        # requirement per Netgate or OPNsense docs.
        sev = "LOW"
        iface = (_interfaces_of(rule) or ["lan"])[0]
        return IPv6Finding(
            severity=sev,
            rule_id=rule.get("uuid", "auto_lan_v6"),
            rule_description=rule.get("description", "Default allow LAN IPv6 to any rule"),
            issue="Default allow LAN IPv6 to any rule (Hinweis, keine Schwachstelle)",
            reason=(
                "Diese Regel erlaubt LAN Hosts, ausgehend IPv6 Verbindungen zu starten. "
                "Rueckverkehr wird vom stateful Filter ueber den State zugelassen. "
                "Die Regel macht interne Hosts NICHT aus dem Internet erreichbar. "
                "Der Schutz gegen unsolicited eingehenden Verkehr liegt auf WAN: "
                "die Default-Deny-Regel in filter.lib.inc ist als inet46 registriert "
                "und greift fuer v4 und v6 gleichermassen, solange keine WAN Pass "
                "Regel den Verkehr durchlaesst. Bei IPv6 gibt es kein NAT, das wird "
                "in der Netgate Doku ausdruecklich so beschrieben, NAT war nie die "
                "Security-Grenze, sondern stateful Filtering plus Default Deny."
            ),
            solution=(
                "Kein Handlungsbedarf zwingend. Optional als defense in depth eine "
                "explizite Block Regel auf WAN inbound (Source any, Destination "
                "LAN net, ipprotocol inet6, Log aktiv), damit die Absicht im "
                "Regelwerk sichtbar ist. Wenn IPv6 aus LAN gar nicht raus soll, "
                "die LAN Regel durch gezielte Allow Regeln ersetzen."
            ),
            rule_details=rule,
            interface=iface,
            opnsense_path="Firewall > Rules > WAN",
            implementation_steps=[
                "1. Firewall > Rules > WAN oeffnen.",
                "2. Pruefen, dass keine Pass Regel mit Destination 'LAN net' oder dem GUA Praefix existiert.",
                ("3. " + ("Defense in depth Regel ist bereits vorhanden, nichts zu tun." if wan_block_present
                         else "Optional defense in depth Regel anlegen, Action Block, Interface WAN, "
                              "Direction in, TCP/IP Version IPv6, Protocol any, Source any, "
                              "Destination 'LAN net', Log aktivieren.")),
                "4. ICMPv6 nicht pauschal blockieren, NDP und PMTUD bleiben noetig (RFC 4890).",
            ],
            suggested_rule=None if wan_block_present else _suggest_wan_block_to_lan_v6(),
        )

    def _wan_v6_pass_finding(self, rule: dict) -> IPv6Finding:
        iface = (_interfaces_of(rule) or ["wan"])[0]
        return IPv6Finding(
            severity="HIGH",
            rule_id=rule.get("uuid", ""),
            rule_description=rule.get("description") or rule.get("uuid", "WAN v6 pass"),
            issue="WAN Inbound IPv6 Pass Regel, exponiert moeglicherweise interne Dienste",
            reason=(
                "Eine WAN inbound Pass Regel fuer IPv6 oeffnet einen Pfad ins LAN, "
                "ohne dass NAT das Ziel verschleiert. Wenn diese Regel nicht eng "
                "auf bestimmte Dienste, Ports und Ziele beschraenkt ist, sind interne "
                "Hosts mit globalem v6 direkt aus dem Internet erreichbar."
            ),
            solution=(
                "Regel pruefen. Source ggf. auf bekannte Quellen, Destination auf "
                "konkrete Hosts oder Aliase, Port auf konkrete Werte. Wenn die "
                "Regel nicht zwingend gewollt ist, deaktivieren oder loeschen."
            ),
            rule_details=rule,
            interface=iface,
            opnsense_path=f"Firewall > Rules > {iface.upper()}",
            implementation_steps=[
                f"1. Firewall > Rules > {iface.upper()} oeffnen.",
                f"2. Regel '{rule.get('description', rule.get('uuid', ''))[:60]}' suchen.",
                "3. Source, Destination und Port auf das noetige Minimum einschraenken.",
                "4. Bei Unsicherheit Regel deaktivieren und Verbindungstest durchfuehren.",
                "5. Speichern und Apply Changes.",
            ],
        )

    def _parity_finding(self, rule: dict, iface_has_v6: bool) -> IPv6Finding:
        # Missing v6 pass rule is a feature gap, not a security hole.
        # Default-deny on v6 protects the host either way.
        sev = "LOW"
        iface = (_interfaces_of(rule) or ["floating"])[0]
        desc = rule.get("description") or rule.get("uuid", "rule")
        suffix = " (Interface hat aktuell globales v6)" if iface_has_v6 else ""
        return IPv6Finding(
            severity=sev,
            rule_id=rule.get("uuid", ""),
            rule_description=desc,
            issue="IPv4 Pass Regel ohne IPv6 Pendant" + suffix,
            reason=(
                "Auf Interface " + iface + " existiert eine inet Pass Regel ohne "
                "inet6 oder inet46 Sibling mit gleichen Selektoren. Sicherheitsmaessig "
                "ist das kein Loch, der v6 Verkehr wird durch Default Deny verworfen. "
                "Es ist aber eine Feature Luecke wenn der gleiche Dienst auch ueber "
                "IPv6 erreichbar sein soll."
            ),
            solution=(
                "Wenn der Dienst auch v6 koennen soll, Regel auf inet46 umstellen "
                "oder eine zweite inet6 Regel anlegen. Sonst Finding ignorieren."
            ),
            rule_details=rule,
            interface=iface,
            opnsense_path="Firewall > Rules > " + iface.upper(),
            implementation_steps=[
                "1. Firewall > Rules > " + iface.upper() + " oeffnen.",
                "2. Regel duplizieren oder auf inet46 stellen.",
                "3. ipprotocol auf inet6 oder inet46 setzen.",
                "4. Speichern und Apply Changes.",
            ],
            suggested_rule=_suggest_v6_mirror(rule),
        )
