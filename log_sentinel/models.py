from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class SshEvent:
    ts: datetime
    kind: str  # "failed" | "accepted"
    user: str
    ip: str
    method: Optional[str] = None


@dataclass(frozen=True)
class WebEvent:
    ts: datetime
    ip: str
    method: str
    path: str
    status: int
    size: int
    referrer: str
    user_agent: str


@dataclass
class Finding:
    rule: str
    severity: str
    ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    summary: str
    mitre: str
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "ip": self.ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "summary": self.summary,
            "mitre": self.mitre,
            "evidence": self.evidence,
        }
