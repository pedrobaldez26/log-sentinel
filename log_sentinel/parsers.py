"""Leitura de auth.log (sshd) e access.log (formato combined do nginx/Apache).

Linhas que não casam são ignoradas: log de produção tem ruído de todo tipo, e o
parser não deve derrubar a análise por causa de uma linha estranha.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator, Optional

from .models import SshEvent, WebEvent

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_FAILED = re.compile(r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+")
_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+")

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)
_WEB_TS = re.compile(r"^(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")


def parse_ssh_line(line: str, year: int) -> Optional[SshEvent]:
    """O syslog não traz o ano, então ele vem de fora (veja a limitação no README)."""
    m = _SYSLOG.match(line.rstrip("\n"))
    if not m or m["mon"] not in MONTHS:
        return None

    msg = m["msg"]
    hit = _FAILED.match(msg)
    kind = "failed"
    if not hit:
        hit = _ACCEPTED.match(msg)
        kind = "accepted"
    if not hit:
        return None

    hh, mm, ss = (int(x) for x in m["time"].split(":"))
    try:
        ts = datetime(year, MONTHS[m["mon"]], int(m["day"]), hh, mm, ss)
    except ValueError:  # ex.: 29/fev em ano não bissexto
        return None
    return SshEvent(ts=ts, kind=kind, user=hit["user"], ip=hit["ip"], method=hit["method"])


def parse_web_line(line: str) -> Optional[WebEvent]:
    m = _COMBINED.match(line.rstrip("\n"))
    if not m:
        return None
    ts = _parse_web_ts(m["ts"])
    if ts is None:
        return None
    return WebEvent(
        ts=ts,
        ip=m["ip"],
        method=m["method"],
        path=m["path"],
        status=int(m["status"]),
        size=int(m["size"]) if m["size"].isdigit() else 0,
        referrer=m["ref"],
        user_agent=m["ua"],
    )


def _parse_web_ts(text: str) -> Optional[datetime]:
    m = _WEB_TS.match(text)
    if not m or m[2] not in MONTHS:
        return None
    day, mon, year, hh, mm, ss, sign, oh, om = m.groups()
    try:
        local = datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss))
    except ValueError:
        return None
    offset = timedelta(hours=int(oh), minutes=int(om))
    # normaliza para UTC "ingênuo", o mesmo referencial dos eventos de SSH (que não têm fuso)
    return local - offset if sign == "+" else local + offset


def read_ssh(lines: Iterable[str], year: int) -> Iterator[SshEvent]:
    for line in lines:
        ev = parse_ssh_line(line, year)
        if ev:
            yield ev


def read_web(lines: Iterable[str]) -> Iterator[WebEvent]:
    for line in lines:
        ev = parse_web_line(line)
        if ev:
            yield ev
