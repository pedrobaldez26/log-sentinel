"""Regras de detecção. Cada uma recebe eventos e devolve uma lista de Finding.

Todas são janelas deslizantes por IP de origem. Os limiares são parâmetros porque
o que é "muito" depende do serviço: 5 falhas em 10 minutos é suspeito em um
servidor SSH pessoal e é só terça-feira em um portal com milhares de usuários.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Dict, Iterable, List, Sequence, Tuple, TypeVar
from urllib.parse import unquote

from .models import Finding, SshEvent, WebEvent

T = TypeVar("T")

# T1110 = Brute Force, .003 = Password Spraying; T1595 = Active Scanning; T1190 = Exploit Public-Facing Application
MITRE_BRUTE = "T1110"
MITRE_SPRAY = "T1110.003"
MITRE_SCAN = "T1595"
MITRE_EXPLOIT = "T1190"


@dataclass
class Thresholds:
    ssh_failures: int = 5
    ssh_window: timedelta = timedelta(minutes=10)
    spray_users: int = 5
    success_after_failures: int = 5
    success_window: timedelta = timedelta(minutes=30)
    web_404s: int = 15
    web_window: timedelta = timedelta(minutes=5)
    web_login_failures: int = 10


def densest_window(
    items: Sequence[T], key: Callable[[T], datetime], window: timedelta
) -> Tuple[int, int]:
    """Dentro de `window`, qual o maior trecho de itens (ordenados por tempo)?
    Devolve (índice inicial, índice final) inclusivos. Dois ponteiros, O(n)."""
    best = (0, -1)
    left = 0
    for right in range(len(items)):
        while key(items[right]) - key(items[left]) > window:
            left += 1
        if right - left > best[1] - best[0]:
            best = (left, right)
    return best


def _by_ip(events: Iterable[T], ip_of: Callable[[T], str], ts_of: Callable[[T], datetime]) -> Dict[str, List[T]]:
    groups: Dict[str, List[T]] = defaultdict(list)
    for ev in events:
        groups[ip_of(ev)].append(ev)
    for evs in groups.values():
        evs.sort(key=ts_of)
    return groups


def _severity_by_count(count: int, high_at: int) -> str:
    return "high" if count >= high_at else "medium"


# ---------------------------------------------------------------- SSH


def ssh_bruteforce(events: Iterable[SshEvent], th: Thresholds) -> List[Finding]:
    failures = (e for e in events if e.kind == "failed")
    out: List[Finding] = []
    for ip, evs in _by_ip(failures, lambda e: e.ip, lambda e: e.ts).items():
        lo, hi = densest_window(evs, lambda e: e.ts, th.ssh_window)
        count = hi - lo + 1
        if count < th.ssh_failures:
            continue
        burst = evs[lo : hi + 1]
        users = sorted({e.user for e in burst})
        out.append(
            Finding(
                rule="ssh-bruteforce",
                severity=_severity_by_count(count, th.ssh_failures * 4),
                ip=ip,
                first_seen=burst[0].ts,
                last_seen=burst[-1].ts,
                count=count,
                summary=f"{count} falhas de login SSH em {_fmt(th.ssh_window)} (usuários: {', '.join(users[:5])}{'…' if len(users) > 5 else ''})",
                mitre=MITRE_BRUTE,
                evidence=[f"{e.ts:%H:%M:%S} Failed {e.method} para {e.user}" for e in burst[:5]],
            )
        )
    return out


SPRAY_MAX_ATTEMPTS_PER_USER = 4


def ssh_password_spray(events: Iterable[SshEvent], th: Thresholds) -> List[Finding]:
    """Muitos usuários diferentes a partir do mesmo IP, com poucas tentativas em cada um:
    o ataque testa poucas senhas em muitas contas para fugir de bloqueio por conta.

    Olha o trecho mais denso de falhas do IP. Se há poucos usuários e muitas tentativas por
    usuário, é força bruta de dicionário (outra regra), não spraying."""
    failures = (e for e in events if e.kind == "failed")
    out: List[Finding] = []
    for ip, evs in _by_ip(failures, lambda e: e.ip, lambda e: e.ts).items():
        lo, hi = densest_window(evs, lambda e: e.ts, th.ssh_window)
        burst = evs[lo : hi + 1]
        users = {e.user for e in burst}
        if len(users) < th.spray_users or len(burst) / len(users) > SPRAY_MAX_ATTEMPTS_PER_USER:
            continue
        out.append(
            Finding(
                rule="ssh-password-spray",
                severity="high",
                ip=ip,
                first_seen=burst[0].ts,
                last_seen=burst[-1].ts,
                count=len(burst),
                summary=f"{len(users)} usuários diferentes tentados em {_fmt(th.ssh_window)}, ~{len(burst) / len(users):.1f} tentativas por usuário",
                mitre=MITRE_SPRAY,
                evidence=[f"usuários: {', '.join(sorted(users)[:10])}"],
            )
        )
    return out


def ssh_success_after_failures(events: Sequence[SshEvent], th: Thresholds) -> List[Finding]:
    """O achado mais importante: o atacante acertou. Login aceito logo depois de uma
    sequência de falhas vindas do mesmo IP."""
    failures = _by_ip((e for e in events if e.kind == "failed"), lambda e: e.ip, lambda e: e.ts)
    out: List[Finding] = []
    seen = set()
    for ev in sorted((e for e in events if e.kind == "accepted"), key=lambda e: e.ts):
        prior = [f for f in failures.get(ev.ip, []) if timedelta(0) <= ev.ts - f.ts <= th.success_window]
        if len(prior) < th.success_after_failures or (ev.ip, ev.user) in seen:
            continue
        seen.add((ev.ip, ev.user))
        out.append(
            Finding(
                rule="ssh-success-after-failures",
                severity="critical",
                ip=ev.ip,
                first_seen=prior[0].ts,
                last_seen=ev.ts,
                count=len(prior) + 1,
                summary=f"login aceito para '{ev.user}' após {len(prior)} falhas em {_fmt(th.success_window)}: possível conta comprometida",
                mitre=MITRE_BRUTE,
                evidence=[f"{ev.ts:%H:%M:%S} Accepted {ev.method} para {ev.user}"],
            )
        )
    return out


# ---------------------------------------------------------------- Web

SENSITIVE_PATHS = re.compile(
    r"(?i)(^|/)(\.env(\.\w+)?|\.git(/|$)|\.svn|\.DS_Store|wp-config\.php(\.bak)?|phpmyadmin|pma/|"
    r"config\.(php|json|yml|yaml)(\.bak)?|backup\.(zip|sql|tar\.gz)|id_rsa|\.aws/credentials|"
    r"server-status|actuator/(env|heapdump)|adminer\.php)"
)

ATTACK_SIGNATURES = [
    ("sql-injection", re.compile(r"(?i)(\bunion\b.{0,20}\bselect\b|'\s*or\s*'?\d+'?\s*=\s*'?\d+|\bsleep\s*\(\s*\d+\s*\)|information_schema|;\s*drop\s+table)")),
    ("xss", re.compile(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=)")),
    ("path-traversal", re.compile(r"(\.\./){2,}|\.\.\\|/etc/passwd|/proc/self/environ")),
    ("log4shell", re.compile(r"(?i)\$\{\s*jndi\s*:")),
    ("command-injection", re.compile(r"(?i)(;|\||`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b")),
]

SCANNER_UAS = re.compile(r"(?i)(sqlmap|nikto|gobuster|dirbuster|wfuzz|ffuf|nmap|masscan|zgrab|wpscan|acunetix|nessus|openvas|hydra)")
LOGIN_PATH = re.compile(r"(?i)(login|signin|sign-in|/auth|wp-login|xmlrpc)")


def _decode(value: str) -> str:
    # decodifica duas vezes: atacante costuma duplo-codificar para passar por filtros simples
    return unquote(unquote(value))


def web_scanning(events: Iterable[WebEvent], th: Thresholds) -> List[Finding]:
    """Muitos 404 seguidos do mesmo IP: enumeração de diretórios por wordlist."""
    not_found = (e for e in events if e.status == 404)
    out: List[Finding] = []
    for ip, evs in _by_ip(not_found, lambda e: e.ip, lambda e: e.ts).items():
        lo, hi = densest_window(evs, lambda e: e.ts, th.web_window)
        count = hi - lo + 1
        if count < th.web_404s:
            continue
        burst = evs[lo : hi + 1]
        out.append(
            Finding(
                rule="web-scanning",
                severity=_severity_by_count(count, th.web_404s * 4),
                ip=ip,
                first_seen=burst[0].ts,
                last_seen=burst[-1].ts,
                count=count,
                summary=f"{count} respostas 404 em {_fmt(th.web_window)}: enumeração de caminhos",
                mitre=MITRE_SCAN,
                evidence=[e.path for e in burst[:5]],
            )
        )
    return out


def web_sensitive_files(events: Iterable[WebEvent], th: Thresholds) -> List[Finding]:
    out: List[Finding] = []
    for ip, evs in _by_ip(events, lambda e: e.ip, lambda e: e.ts).items():
        hits = [e for e in evs if SENSITIVE_PATHS.search(_decode(e.path.split("?", 1)[0]))]
        if not hits:
            continue
        exposed = [e for e in hits if 200 <= e.status < 300]
        out.append(
            Finding(
                rule="web-sensitive-files",
                severity="critical" if exposed else "medium",
                ip=ip,
                first_seen=hits[0].ts,
                last_seen=hits[-1].ts,
                count=len(hits),
                summary=(
                    f"acesso a arquivo sensível COM SUCESSO (HTTP {exposed[0].status}): {exposed[0].path}"
                    if exposed
                    else f"{len(hits)} tentativas de acesso a arquivos sensíveis (todas recusadas)"
                ),
                mitre=MITRE_SCAN,
                evidence=[f"{e.status} {e.path}" for e in hits[:5]],
            )
        )
    return out


def web_attack_signatures(events: Iterable[WebEvent], th: Thresholds) -> List[Finding]:
    out: List[Finding] = []
    for ip, evs in _by_ip(events, lambda e: e.ip, lambda e: e.ts).items():
        matches: List[Tuple[str, WebEvent]] = []
        for e in evs:
            haystack = _decode(e.path) + " " + e.user_agent
            for name, pattern in ATTACK_SIGNATURES:
                if pattern.search(haystack):
                    matches.append((name, e))
                    break
        if not matches:
            continue
        kinds = sorted({name for name, _ in matches})
        out.append(
            Finding(
                rule="web-attack-signatures",
                severity="high",
                ip=ip,
                first_seen=matches[0][1].ts,
                last_seen=matches[-1][1].ts,
                count=len(matches),
                summary=f"{len(matches)} requisições com padrão de ataque ({', '.join(kinds)})",
                mitre=MITRE_EXPLOIT,
                evidence=[f"{e.status} {_decode(e.path)[:90]}" for _, e in matches[:5]],
            )
        )
    return out


def web_scanner_agents(events: Iterable[WebEvent], th: Thresholds) -> List[Finding]:
    out: List[Finding] = []
    for ip, evs in _by_ip(events, lambda e: e.ip, lambda e: e.ts).items():
        hits = [e for e in evs if SCANNER_UAS.search(e.user_agent)]
        if not hits:
            continue
        tool = SCANNER_UAS.search(hits[0].user_agent).group(1).lower()  # type: ignore[union-attr]
        out.append(
            Finding(
                rule="web-scanner-agent",
                severity="medium",
                ip=ip,
                first_seen=hits[0].ts,
                last_seen=hits[-1].ts,
                count=len(hits),
                summary=f"user-agent de ferramenta de varredura ({tool})",
                mitre=MITRE_SCAN,
                evidence=[hits[0].user_agent[:100]],
            )
        )
    return out


def web_login_bruteforce(events: Iterable[WebEvent], th: Thresholds) -> List[Finding]:
    attempts = (
        e for e in events
        if e.method == "POST" and e.status in (401, 403) and LOGIN_PATH.search(e.path)
    )
    out: List[Finding] = []
    for ip, evs in _by_ip(attempts, lambda e: e.ip, lambda e: e.ts).items():
        lo, hi = densest_window(evs, lambda e: e.ts, th.web_window)
        count = hi - lo + 1
        if count < th.web_login_failures:
            continue
        burst = evs[lo : hi + 1]
        out.append(
            Finding(
                rule="web-login-bruteforce",
                severity="high",
                ip=ip,
                first_seen=burst[0].ts,
                last_seen=burst[-1].ts,
                count=count,
                summary=f"{count} logins web recusados em {_fmt(th.web_window)} em {burst[0].path}",
                mitre=MITRE_BRUTE,
                evidence=[f"{e.ts:%H:%M:%S} POST {e.path} -> {e.status}" for e in burst[:3]],
            )
        )
    return out


def run_ssh(events: Sequence[SshEvent], th: Thresholds) -> List[Finding]:
    return ssh_bruteforce(events, th) + ssh_password_spray(events, th) + ssh_success_after_failures(events, th)


def run_web(events: Sequence[WebEvent], th: Thresholds) -> List[Finding]:
    return (
        web_scanning(events, th)
        + web_sensitive_files(events, th)
        + web_attack_signatures(events, th)
        + web_scanner_agents(events, th)
        + web_login_bruteforce(events, th)
    )


def _fmt(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    return f"{minutes} min" if minutes else f"{int(delta.total_seconds())} s"
