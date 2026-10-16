"""Generates SAFE synthetic logs (documentation IP ranges 203.0.113.x, 198.51.100.x, 192.0.2.x)."""
import random
from datetime import datetime, timedelta
random.seed(7)
T0 = datetime(2026, 10, 2, 9, 0, 0)
def apache(t, ip, m, url, st, user="-"):
    return (t, f'{ip} - {user} [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{m} {url} HTTP/1.1" {st} {random.randint(200,5000)}')
def ssh(t, ip, user, ok):
    s = "Accepted" if ok else "Failed"; inv = "" if ok else "invalid user " if user != "alice" else ""
    return (t, f'{t.strftime("%b %e %H:%M:%S")} server sshd[{random.randint(1000,9999)}]: {s} password for {inv}{user} from {ip} port {random.randint(30000,60000)} ssh2')
def fw(t, ip, port):
    return (t, f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} ACTION=DENY SRC={ip} DST=10.0.0.5 PROTO=TCP DPT={port}')
def normal_web(n, start=0, span=1800):
    L = []
    for _ in range(n):
        t = T0 + timedelta(seconds=start + random.randint(0, span)); ip = f"192.168.1.{random.randint(10,17)}"
        url = random.choice(["/", "/index.html", "/products", "/about", "/contact", "/static/app.js"])
        L.append(apache(t, ip, "GET", url, random.choices([200, 304, 404], [88, 8, 4])[0]))
    for k in range(4): L.append(apache(T0 + timedelta(seconds=300 * k + 20), "192.168.1.10", "POST", "/login", 200, "alice"))
    return L
def write(name, lines):
    lines.sort(key=lambda x: x[0])
    open(name, "w").write("\n".join(l for _, l in lines) + "\n")
def brute_ssh(ip, start, n, step=1.5, then_ok=True):
    L = [ssh(T0 + timedelta(seconds=start + i * step), ip, random.choice(["root", "admin", "test"]), False) for i in range(n)]
    if then_ok: L.append(ssh(T0 + timedelta(seconds=start + n * step + 2), ip, "admin", True))
    return L
def scan(ip, start, ports, step=0.7): return [fw(T0 + timedelta(seconds=start + i * step), ip, p) for i, p in enumerate(ports)]

write("sample_normal.log", normal_web(160))
write("sample_web_access.log", normal_web(120) + [apache(T0 + timedelta(seconds=400 + i * 3), "198.51.100.23", "GET", p, 404) for i, p in enumerate(["/wp-login.php", "/xmlrpc.php", "/.git/config", "/backup.zip"] * 2)]
      + [apache(T0 + timedelta(seconds=900 + i), "192.168.1.14", "GET", "/api/report", 500) for i in range(6)])
write("sample_bruteforce.log", [ssh(T0 + timedelta(seconds=i * 200), "192.168.1.10", "alice", True) for i in range(6)]
      + brute_ssh("203.0.113.50", 600, 40) + [ssh(T0 + timedelta(seconds=700 + i * 120), "198.51.100.23", "bob", False) for i in range(3)])
write("sample_portscan.log", [fw(T0 + timedelta(seconds=i * 30), f"192.168.1.{10 + i % 4}", random.choice([80, 443])) for i in range(40)]
      + scan("198.51.100.77", 300, list(range(20, 90))) + scan("203.0.113.9", 600, [22, 80, 443, 3389, 8080, 21, 25, 3306, 5432, 445, 139, 53]))
mixed = normal_web(150, 0, 1700) + brute_ssh("203.0.113.50", 500, 30)
mixed += [apache(T0 + timedelta(seconds=800 + i * 1.2), "203.0.113.50", "POST", "/login", 401) for i in range(25)] + [apache(T0 + timedelta(seconds=835), "203.0.113.50", "POST", "/login", 302, "admin")]
mixed += [apache(T0 + timedelta(seconds=1000 + i * 2), "198.51.100.23", "GET", p, random.choice([403, 404, 403])) for i, p in enumerate(["/admin", "/etc/passwd", "/private/db", "/admin/config", "/.env", "/admin/users"] * 2)]
mixed += [apache(T0 + timedelta(seconds=1200 + i * 0.4), "192.0.2.99", "GET", "/products", 200) for i in range(130)]
mixed += scan("198.51.100.77", 1400, list(range(1, 61)))
write("sample_mixed_attack.log", mixed)
