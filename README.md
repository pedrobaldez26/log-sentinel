# log-sentinel

Lê logs de SSH (`auth.log`) e de servidor web (`access.log` no formato combined do nginx/Apache) e aponta o que parece ataque: força bruta, password spraying, varredura de diretórios, tentativa de SQL injection e, principalmente, **login aceito depois de uma sequência de falhas**, que é o sinal de que alguém entrou.

Feito para ser pequeno e legível: só biblioteca padrão do Python, nenhuma dependência.

## Exemplo

Os arquivos em `samples/` são sintéticos (gerados por `scripts/generate_samples.py`, com IPs das faixas reservadas para documentação). Rodando sobre eles:

```
$ log-sentinel --ssh samples/auth.log --web samples/access.log --year 2026 --min-severity high

Resumo: 2 critical, 7 high

[CRITICAL] ssh-success-after-failures  203.0.113.99     07/11 22:41 → 22:42  (T1110)
           login aceito para 'deploy' após 14 falhas em 30 min: possível conta comprometida
[CRITICAL] web-sensitive-files         203.0.113.200    07/11 07:48 → 07:48  (T1595)
           acesso a arquivo sensível COM SUCESSO (HTTP 200): /.env
[HIGH    ] web-scanning                198.51.100.77    07/11 04:02 → 04:04  (T1595)
           130 respostas 404 em 5 min: enumeração de caminhos
[HIGH    ] ssh-bruteforce              203.0.113.45     07/11 03:12 → 03:19  (T1110)
           58 falhas de login SSH em 10 min (usuários: admin, oracle, root, test, ubuntu)
[HIGH    ] web-login-bruteforce        192.0.2.55       07/11 13:20 → 13:22  (T1110)
           32 logins web recusados em 5 min em /login
[HIGH    ] ssh-bruteforce              198.51.100.23    07/11 05:30 → 05:39  (T1110)
           24 falhas de login SSH em 10 min (usuários: ana, backup, carlos, deploy, git…)
[HIGH    ] ssh-password-spray          198.51.100.23    07/11 05:30 → 05:39  (T1110.003)
           12 usuários diferentes tentados em 10 min, ~2.0 tentativas por usuário
[HIGH    ] web-attack-signatures       203.0.113.12     07/11 06:15 → 06:16  (T1190)
           24 requisições com padrão de ataque (sql-injection)
[HIGH    ] web-attack-signatures       198.51.100.140   07/11 11:02 → 11:02  (T1190)
           2 requisições com padrão de ataque (log4shell, path-traversal)
```

Cada achado traz a técnica do [MITRE ATT&CK](https://attack.mitre.org/) correspondente (`T1110` brute force, `T1110.003` password spraying, `T1595` active scanning, `T1190` exploit de aplicação pública), o que ajuda a encaixar o resultado em um relatório de incidente. Com `-v` aparecem as linhas de evidência de cada achado.

## O que ele detecta

| Regra | Sinal | Severidade |
|-------|-------|-----------|
| `ssh-bruteforce` | 5+ falhas do mesmo IP em 10 min | média; alta a partir de 20 falhas |
| `ssh-password-spray` | 5+ usuários distintos, com até ~4 tentativas por usuário | alta |
| `ssh-success-after-failures` | login aceito após 5+ falhas do mesmo IP em 30 min | **crítica** |
| `web-scanning` | 15+ respostas 404 do mesmo IP em 5 min | média; alta a partir de 60 |
| `web-sensitive-files` | requisição a `.env`, `.git`, `wp-config.php`, `phpmyadmin`... | média; **crítica** se respondeu 2xx |
| `web-attack-signatures` | SQL injection, XSS, path traversal, Log4Shell, injeção de comando | alta |
| `web-scanner-agent` | user-agent de sqlmap, nikto, gobuster, nmap, wpscan... | média |
| `web-login-bruteforce` | 10+ `POST` de login com 401/403 em 5 min | alta |

Todos os limiares são parâmetros (`--ssh-failures`, `--ssh-window`, `--web-404s`...). O que é "muito" depende do serviço: 5 falhas em 10 minutos é suspeito em um servidor pessoal e é rotina em um portal com milhares de usuários.

### Detalhes que importam

- **Spray não é força bruta.** Um dicionário de 5 usuários com 58 tentativas é força bruta de dicionário; spraying é o contrário, muitas contas com poucas tentativas cada (para fugir de bloqueio por conta). A regra olha tentativas por usuário para não confundir os dois. Está nos testes.
- **Janela deslizante com dois ponteiros** (`densest_window`), O(n) por IP, em vez de agrupar por minuto. Agrupamento fixo perde ataque que atravessa a virada do minuto.
- **Payload codificado.** Caminhos são decodificados duas vezes antes de casar assinatura, porque atacante costuma duplo-codificar para passar por filtro simples (`%2527` -> `%27` -> `'`).
- **Fuso.** Logs web têm fuso (`+0200`) e o syslog não. Tudo é normalizado para UTC antes de comparar.
- **Linha estranha não derruba a análise.** Log de produção tem lixo; linhas que não casam são ignoradas.

## Uso

Python 3.9 ou mais novo.

```bash
pip install -e .

log-sentinel --ssh /var/log/auth.log --web /var/log/nginx/access.log
log-sentinel --ssh auth.log --year 2026 --format json > achados.json
log-sentinel --web access.log --min-severity high -v
```

O `auth.log` não registra o ano; use `--year` ao analisar log de um ano passado (o padrão é o ano atual).

### Em cron ou CI

`--fail-on` faz o comando sair com código 2 quando houver achado do nível indicado ou acima:

```bash
log-sentinel --ssh /var/log/auth.log --fail-on critical || alerta.sh
```

### Lista de bloqueio

```bash
log-sentinel --ssh auth.log --web access.log --blocklist bloquear.txt --allow 203.0.113.7
```

Grava, um por linha, os IPs de achados `high` e `critical`. **Nunca** inclui endereços de rede interna (RFC 1918, loopback, link-local, CGNAT, ULA) nem os passados em `--allow`: bloquear a própria rede por causa de um falso positivo é pior que o ataque. A ferramenta só gera a lista, quem aplica no firewall é você, depois de olhar.

## Testes

```bash
pip install -e '.[dev]'
pytest
```

34 testes: parsers (inclusive linhas inválidas, IPv6 e fuso), cada regra no limiar (4 falhas não alertam, 5 sim; 5 falhas espalhadas em horas não alertam), falsos positivos (tráfego normal não gera achado) e a CLI de ponta a ponta sobre os logs de exemplo.

## Limitações

- Só `sshd` com autenticação por senha/chave (`Failed`/`Accepted`). Não lê `journalctl`, nem o formato ISO 8601 do rsyslog.
- Não correlaciona SSH com web nem entre servidores diferentes.
- Assinaturas de ataque são regex, não um WAF: pegam o óbvio e o que scanner automático faz, não um atacante cuidadoso. Podem dar falso positivo em busca legítima que cite `UNION SELECT`.
- IP atrás de proxy/CDN aparece como o IP do proxy, a menos que o log use `X-Forwarded-For`.
- Analisa arquivo, não acompanha em tempo real (`tail -f`).

## Licença

MIT
