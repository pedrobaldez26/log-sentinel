from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .detectors import Thresholds, run_ssh, run_web
from .models import SEVERITIES, Finding
from .parsers import read_ssh, read_web
from .report import at_least, blocklist, sort_findings, to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-sentinel",
        description="Procura brute force, password spraying e varredura em logs de SSH e nginx/Apache.",
    )
    p.add_argument("--ssh", metavar="ARQUIVO", help="auth.log com linhas do sshd")
    p.add_argument("--web", metavar="ARQUIVO", help="access.log no formato combined")
    p.add_argument("--year", type=int, default=datetime.now().year, help="ano do auth.log (o syslog não traz). Padrão: ano atual")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("-v", "--verbose", action="store_true", help="mostra evidências de cada achado")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low", help="esconde achados abaixo disso")
    p.add_argument("--fail-on", choices=SEVERITIES, help="sai com código 2 se houver achado desse nível ou acima (para CI/cron)")

    g = p.add_argument_group("limiares")
    g.add_argument("--ssh-failures", type=int, default=5, help="falhas SSH na janela (padrão 5)")
    g.add_argument("--ssh-window", type=int, default=10, help="janela SSH em minutos (padrão 10)")
    g.add_argument("--spray-users", type=int, default=5, help="usuários distintos para password spraying (padrão 5)")
    g.add_argument("--web-404s", type=int, default=15, help="404s na janela web (padrão 15)")
    g.add_argument("--web-window", type=int, default=5, help="janela web em minutos (padrão 5)")
    g.add_argument("--web-login-failures", type=int, default=10, help="logins web recusados na janela (padrão 10)")

    b = p.add_argument_group("bloqueio")
    b.add_argument("--blocklist", metavar="ARQUIVO", help="grava os IPs públicos de achados high/critical, um por linha")
    b.add_argument("--allow", action="append", default=[], metavar="IP", help="IP que nunca entra na blocklist (repita para vários)")

    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def analyze(args: argparse.Namespace) -> List[Finding]:
    th = Thresholds(
        ssh_failures=args.ssh_failures,
        ssh_window=timedelta(minutes=args.ssh_window),
        spray_users=args.spray_users,
        web_404s=args.web_404s,
        web_window=timedelta(minutes=args.web_window),
        web_login_failures=args.web_login_failures,
    )
    findings: List[Finding] = []
    if args.ssh:
        with open(args.ssh, encoding="utf-8", errors="replace") as fh:
            findings += run_ssh(list(read_ssh(fh, args.year)), th)
    if args.web:
        with open(args.web, encoding="utf-8", errors="replace") as fh:
            findings += run_web(list(read_web(fh)), th)
    return sort_findings(findings)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.ssh and not args.web:
        parser.error("informe pelo menos um de --ssh ou --web")
    for path in (args.ssh, args.web):
        if path and not Path(path).is_file():
            print(f"log-sentinel: arquivo não encontrado: {path}", file=sys.stderr)
            return 1

    findings = analyze(args)

    if args.blocklist:
        ips = blocklist(findings, "high", args.allow)
        Path(args.blocklist).write_text("".join(ip + "\n" for ip in ips))
        print(f"{len(ips)} IP(s) gravados em {args.blocklist}", file=sys.stderr)

    shown = at_least(findings, args.min_severity)
    sys.stdout.write(to_json(shown) + "\n" if args.format == "json" else to_text(shown, args.verbose))

    if args.fail_on and at_least(findings, args.fail_on):
        return 2
    return 0
