import json
from pathlib import Path

import pytest

from log_sentinel.cli import main
from log_sentinel.models import Finding
from log_sentinel.report import blocklist
from datetime import datetime

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
ARGS = ["--ssh", str(SAMPLES / "auth.log"), "--web", str(SAMPLES / "access.log"), "--year", "2026"]


def run_json(capsys, *extra):
    code = main([*ARGS, "--format", "json", *extra])
    return code, json.loads(capsys.readouterr().out)


def test_amostras_geram_os_achados_esperados(capsys):
    code, findings = run_json(capsys)
    assert code == 0
    got = {(f["rule"], f["ip"]) for f in findings}
    assert ("ssh-success-after-failures", "203.0.113.99") in got
    assert ("web-sensitive-files", "203.0.113.200") in got
    assert ("ssh-bruteforce", "203.0.113.45") in got
    assert ("ssh-password-spray", "198.51.100.23") in got
    assert ("web-scanning", "198.51.100.77") in got
    assert ("web-attack-signatures", "203.0.113.12") in got
    assert ("web-login-bruteforce", "192.0.2.55") in got
    assert ("web-attack-signatures", "198.51.100.140") in got


def test_usuarios_legitimos_nao_aparecem(capsys):
    _, findings = run_json(capsys)
    ips = {f["ip"] for f in findings}
    assert "192.0.2.10" not in ips  # maria, login normal
    assert "10.0.0.5" not in ips  # errou a senha uma vez
    assert not any(f["ip"].startswith("192.0.2.2") or f["ip"].startswith("192.0.2.3") for f in findings)


def test_dicionario_de_5_usuarios_nao_vira_spray(capsys):
    _, findings = run_json(capsys)
    assert ("ssh-password-spray", "203.0.113.45") not in {(f["rule"], f["ip"]) for f in findings}


def test_ordenado_do_mais_grave_para_o_menos(capsys):
    _, findings = run_json(capsys)
    ranks = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    order = [ranks[f["severity"]] for f in findings]
    assert order == sorted(order, reverse=True)


def test_fail_on_e_min_severity(capsys):
    assert main([*ARGS, "--fail-on", "critical"]) == 2
    capsys.readouterr()
    assert main([*ARGS, "--min-severity", "critical"]) == 0
    out = capsys.readouterr().out
    assert "CRITICAL" in out and "HIGH" not in out


def test_limiares_configuraveis(capsys):
    _, findings = run_json(capsys, "--ssh-failures", "100")
    assert ("ssh-bruteforce", "203.0.113.45") not in {(f["rule"], f["ip"]) for f in findings}


def test_blocklist_so_ips_publicos_de_alta_severidade(tmp_path, capsys):
    out = tmp_path / "block.txt"
    main([*ARGS, "--blocklist", str(out), "--allow", "203.0.113.45"])
    ips = out.read_text().split()
    assert "203.0.113.99" in ips and "203.0.113.200" in ips
    assert "203.0.113.45" not in ips  # na lista de permitidos
    assert "192.0.2.10" not in ips


def test_blocklist_nunca_inclui_enderecos_privados():
    now = datetime(2026, 1, 1)
    f = lambda ip: Finding("r", "critical", ip, now, now, 1, "", "T1110")
    assert blocklist([f("10.0.0.5"), f("192.168.1.9"), f("127.0.0.1"), f("169.254.1.1"), f("nao-e-ip"), f("8.8.8.8")]) == ["8.8.8.8"]


def test_erros_de_uso(capsys):
    with pytest.raises(SystemExit):
        main([])
    assert main(["--ssh", "/nao/existe.log"]) == 1
