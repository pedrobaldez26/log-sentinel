from datetime import datetime

from log_sentinel.parsers import parse_ssh_line, parse_web_line


def test_ssh_falha_com_usuario_valido():
    ev = parse_ssh_line("Nov  7 03:12:08 srv01 sshd[2223]: Failed password for root from 203.0.113.45 port 35838 ssh2", 2026)
    assert ev.kind == "failed"
    assert (ev.user, ev.ip, ev.method) == ("root", "203.0.113.45", "password")
    assert ev.ts == datetime(2026, 11, 7, 3, 12, 8)


def test_ssh_falha_com_usuario_invalido():
    ev = parse_ssh_line("Nov 17 23:59:59 srv sshd[1]: Failed password for invalid user admin from 198.51.100.2 port 22 ssh2", 2026)
    assert (ev.kind, ev.user) == ("failed", "admin")
    assert ev.ts.day == 17


def test_ssh_aceito_publickey_e_ipv6():
    ev = parse_ssh_line("Nov  1 08:00:00 h sshd[9]: Accepted publickey for maria from 2001:db8::1 port 40222 ssh2: RSA SHA256:abc", 2026)
    assert (ev.kind, ev.user, ev.ip, ev.method) == ("accepted", "maria", "2001:db8::1", "publickey")


def test_ssh_ignora_linhas_que_nao_interessam():
    for line in [
        "",
        "lixo qualquer",
        "Nov  7 03:12:08 srv01 sshd[1]: Connection closed by 203.0.113.45 port 1 [preauth]",
        "Nov  7 03:12:08 srv01 cron[1]: Failed password for root from 1.2.3.4 port 22",
        "Xxx  7 03:12:08 srv01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
        "Feb 30 03:12:08 srv01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
    ]:
        assert parse_ssh_line(line, 2026) is None, line


WEB = '203.0.113.12 - - [07/Nov/2026:06:15:03 +0000] "GET /produtos?id=1 HTTP/1.1" 200 900 "https://x.example/" "Mozilla/5.0"'


def test_web_linha_combined():
    ev = parse_web_line(WEB)
    assert (ev.ip, ev.method, ev.path, ev.status, ev.size) == ("203.0.113.12", "GET", "/produtos?id=1", 200, 900)
    assert ev.referrer == "https://x.example/" and ev.user_agent == "Mozilla/5.0"
    assert ev.ts == datetime(2026, 11, 7, 6, 15, 3)


def test_web_normaliza_fuso_para_utc():
    ev = parse_web_line(WEB.replace("+0000", "-0300"))
    assert ev.ts == datetime(2026, 11, 7, 9, 15, 3)
    ev = parse_web_line(WEB.replace("+0000", "+0200"))
    assert ev.ts == datetime(2026, 11, 7, 4, 15, 3)


def test_web_tamanho_com_hifen_e_requisicao_malformada():
    assert parse_web_line(WEB.replace(" 900 ", " - ")).size == 0
    assert parse_web_line('1.2.3.4 - - [07/Nov/2026:06:15:03 +0000] "-" 408 0 "-" "-"') is None
    assert parse_web_line("isso não é um log") is None
    assert parse_web_line(WEB.replace("Nov", "Xyz")) is None
