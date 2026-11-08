from __future__ import annotations

import ipaddress
import json
from typing import Iterable, List, Sequence, Set

from .models import SEVERITIES, Finding


def sort_findings(findings: Iterable[Finding]) -> List[Finding]:
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(findings, key=lambda f: (-rank[f.severity], -f.count, f.ip, f.rule))


def at_least(findings: Iterable[Finding], severity: str) -> List[Finding]:
    floor = SEVERITIES.index(severity)
    return [f for f in findings if SEVERITIES.index(f.severity) >= floor]


def to_json(findings: Sequence[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2)


def to_text(findings: Sequence[Finding], verbose: bool = False) -> str:
    if not findings:
        return "Nenhum achado.\n"

    counts = {s: sum(1 for f in findings if f.severity == s) for s in reversed(SEVERITIES)}
    lines = ["Resumo: " + ", ".join(f"{n} {s}" for s, n in counts.items() if n), ""]
    for f in findings:
        lines.append(f"[{f.severity.upper():8}] {f.rule:27} {f.ip:<16} {f.first_seen:%d/%m %H:%M} → {f.last_seen:%H:%M}  ({f.mitre})")
        lines.append(f"           {f.summary}")
        if verbose:
            lines.extend(f"             · {e}" for e in f.evidence)
    return "\n".join(lines) + "\n"


# Redes que nunca entram na blocklist. A lista é explícita porque `ipaddress.is_private` também
# marca como privadas as faixas de documentação (192.0.2.0/24 etc.), o que atrapalharia os exemplos.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
        "100.64.0.0/10",  # CGNAT
        "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
        "::1/128", "fc00::/7", "fe80::/10",
    )
]


def is_internal(addr) -> bool:
    return any(addr in net for net in INTERNAL_NETWORKS if net.version == addr.version) or addr.is_multicast


def blocklist(findings: Iterable[Finding], minimum: str = "high", allow: Iterable[str] = ()) -> List[str]:
    """IPs para bloquear no firewall.

    Nunca inclui endereço de rede interna (veja INTERNAL_NETWORKS) nem da lista de permitidos: bloquear a
    própria rede por causa de um falso positivo é pior que o ataque."""
    allowed: Set[str] = set(allow)
    ips: Set[str] = set()
    for f in at_least(findings, minimum):
        try:
            addr = ipaddress.ip_address(f.ip)
        except ValueError:
            continue
        if is_internal(addr) or f.ip in allowed:
            continue
        ips.add(f.ip)
    return sorted(ips, key=lambda x: ipaddress.ip_address(x))
