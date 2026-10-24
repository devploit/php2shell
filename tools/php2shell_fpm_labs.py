#!/usr/bin/env python3
"""
php2shell_fpm_labs.py — local nginx + PHP-FPM laboratory (no root, no docker).

Every user-prefix build under lab/fpm/runtime/php-<version>/ gets two HTTP
endpoints (chain + builder) and two FastCGI listeners.  The documented
builds keep their published ports:

    8.4.25  chain http :8130 -> fpm :9021   builder http :8131 -> fpm :9022
    8.4.26  chain http :8110 -> fpm :9001   builder http :8111 -> fpm :9002
    8.4.27  chain http :8120 -> fpm :9011   builder http :8121 -> fpm :9012

Any other build is assigned ports automatically (from :8140 / :9031 up) so
the whole affected version matrix can be calibrated in one lab.

Pools (php-fpm.conf.in):
    chain   memory_limit=8M,  cleanup=On,  save_path=<runtime>/session
    builder memory_limit=64M, cleanup=Off  (builds large session files)

Commands:
    python3 tools/php2shell_fpm_labs.py up [--only 8.4.26]
    python3 tools/php2shell_fpm_labs.py status
    python3 tools/php2shell_fpm_labs.py ports
    python3 tools/php2shell_fpm_labs.py smoke
    python3 tools/php2shell_fpm_labs.py test
    python3 tools/php2shell_fpm_labs.py down
"""

from __future__ import annotations

import argparse
import contextlib
import os
import pwd
import signal
import socket
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LAB = os.path.join(ROOT, "lab", "fpm")
RUNTIME = os.path.join(LAB, "runtime")
WEBROOT = os.path.join(LAB, "webroot")
OUTDIR = os.path.join(WEBROOT, "out")
NGINX_PREFIX = os.path.join(RUNTIME, "nginx")
NGINX_BIN = os.path.join(NGINX_PREFIX, "sbin", "nginx")
NGINX_CONF_DIR = os.path.join(NGINX_PREFIX, "conf")
NGINX_CONF = os.path.join(RUNTIME, "nginx.conf")
PHP_INI = os.path.join(LAB, "php.ini")
FPM_CONF_TMPL = os.path.join(LAB, "php-fpm.conf.in")
NGINX_CONF_TMPL = os.path.join(LAB, "nginx.conf.in")

USER_NAME = pwd.getpwuid(os.getuid()).pw_name
GROUP_NAME = subprocess.run(
    ["id", "-gn"], capture_output=True, text=True
).stdout.strip() or USER_NAME

# The affected version matrix (CVE-2026-109619): every release of the
# patched branches up to (but excluding) the fixed one, plus the newest
# release of the end-of-life branches upstream never fixed (7.2, 7.4).
BRANCHES: tuple[tuple[str, int], ...] = (
    ("7.2", 34),
    ("7.4", 33),
    ("8.2", 34),
    ("8.3", 35),
    ("8.4", 26),
)

# version -> (chain_http, builder_http, chain_fpm, builder_fpm)
# The documented builds keep their published ports; every other build gets
# ports assigned automatically so a whole version matrix fits in one lab.
PINNED_PORTS: dict[str, tuple[int, int, int, int]] = {
    "8.4.25": (8130, 8131, 9021, 9022),
    "8.4.26": (8110, 8111, 9001, 9002),
    "8.4.27": (8120, 8121, 9011, 9012),
    "8.2.35": (8140, 8141, 9031, 9032),
    "8.3.36": (8150, 8151, 9041, 9042),
}
AUTO_HTTP_BASE = 8200
AUTO_FPM_BASE = 9100


def canonical_versions() -> list[str]:
    """Every affected release, in a stable order (drives the port map)."""
    versions = []
    for branch, last in BRANCHES:
        for patch in range(0, last + 1):
            versions.append(f"{branch}.{patch}")
    return versions


def version_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return (0,)


def built_versions() -> list[str]:
    """Versions with a php-fpm binary in the lab runtime."""
    if not os.path.isdir(RUNTIME):
        return []
    versions = []
    for name in os.listdir(RUNTIME):
        if not name.startswith("php-"):
            continue
        version = name[4:]
        if os.path.isfile(os.path.join(RUNTIME, name, "sbin", "php-fpm")):
            versions.append(version)
    return sorted(versions, key=version_key)


def builds_map(versions: list[str] | None = None) -> dict[str, tuple[int, int, int, int]]:
    """Port assignment for the given versions (all built ones by default).

    The ports only depend on the version, not on which other builds happen
    to be present, so a lab started with a different subset still uses the
    documented endpoints.
    """
    versions = versions if versions is not None else built_versions()
    slots = {version: index for index, version in enumerate(canonical_versions())}
    result: dict[str, tuple[int, int, int, int]] = {}
    for version in versions:
        if version in PINNED_PORTS:
            result[version] = PINNED_PORTS[version]
            continue
        index = slots.get(version)
        if index is None:
            # unknown version: park it after the canonical matrix
            index = len(slots) + len(result)
        chain_http = AUTO_HTTP_BASE + 2 * index
        result[version] = (chain_http, chain_http + 1,
                           AUTO_FPM_BASE + 2 * index, AUTO_FPM_BASE + 2 * index + 1)
    return result


BUILDS = builds_map()


def fpm_prefix(version: str) -> str:
    return os.path.join(RUNTIME, f"php-{version}")


def fpm_bin(version: str) -> str:
    return os.path.join(fpm_prefix(version), "sbin", "php-fpm")


def render(template: str, mapping: dict[str, str]) -> str:
    with open(template, encoding="utf-8") as handle:
        text = handle.read()
    for key, value in mapping.items():
        text = text.replace(f"@{key}@", value)
    return text


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def read_pid(path: str) -> int | None:
    try:
        with open(path, encoding="utf-8") as handle:
            pid = int(handle.read().strip())
    except (OSError, ValueError):
        return None
    try:
        os.kill(pid, 0)
        return pid
    except OSError:
        return None


def worker_pids(version: str, pool: str) -> list[int]:
    marker = f"php-fpm: pool {pool}".encode()
    needle = f"php-{version}".encode()
    pids = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as handle:
                data = handle.read()
            if marker in data and needle in data + os.readlink(f"/proc/{name}/exe").encode():
                pids.append(int(name))
        except OSError:
            continue
    return pids


def ensure_dirs(version: str) -> None:
    prefix = fpm_prefix(version)
    for sub in ("logs", "session", "tmp"):
        os.makedirs(os.path.join(prefix, sub), exist_ok=True)
    os.makedirs(OUTDIR, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(os.path.join(prefix, "session"), 0o700)


def write_fpm_conf(version: str) -> str:
    chain_http, builder_http, chain_fpm, builder_fpm = BUILDS[version]
    prefix = fpm_prefix(version)
    rendered = render(FPM_CONF_TMPL, {
        "RUNTIME": prefix,
        "CHAIN_PORT": str(chain_fpm),
        "BUILDER_PORT": str(builder_fpm),
        "USER": USER_NAME,
        "GROUP": GROUP_NAME,
        "WEBROOT": WEBROOT,
        "SAVEDIR": os.path.join(prefix, "session"),
        "VER": version,
    })
    # Directives the build's FPM does not know would fail the config test:
    # decorate_workers_output only exists from PHP 7.3 on.  A suffixed
    # version (7.2.34-asan) is treated as its numeric part.
    try:
        numeric = tuple(int(part) for part in version.split("."))
    except ValueError:
        numeric = tuple(int(part) if part.isdigit() else 99
                        for part in version.split("."))
    if numeric < (7, 3, 0):
        rendered = "\n".join(
            line for line in rendered.splitlines()
            if not line.startswith("decorate_workers_output")) + "\n"
    path = os.path.join(prefix, "php-fpm.conf")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(rendered)
    return path


def write_nginx_conf(versions: list[str]) -> None:
    servers = []
    for version in versions:
        chain_http, builder_http, chain_fpm, builder_fpm = BUILDS[version]
        prefix = fpm_prefix(version)
        for label, http_port, fpm_port in (
            ("chain", chain_http, chain_fpm),
            ("builder", builder_http, builder_fpm),
        ):
            servers.append(f"""
server {{
    listen 127.0.0.1:{http_port};
    server_name _;
    root {WEBROOT};
    access_log {prefix}/logs/{label}-access.log;

    location /out/ {{
        root {WEBROOT};
        default_type text/plain;
        add_header X-Lab-Static "1";
    }}

    location / {{
        include {NGINX_CONF_DIR}/fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass 127.0.0.1:{fpm_port};
    }}
}}""")
    rendered = render(NGINX_CONF_TMPL, {
        "RUNTIME": RUNTIME,
        "NGINX_CONF": NGINX_CONF_DIR,
        "SERVERS": "\n".join(servers),
    })
    with open(NGINX_CONF, "w", encoding="utf-8") as handle:
        handle.write(rendered)


def wait_http(url: str, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def select(only: set[str] | None) -> list[str]:
    """Versions to act on: the --only filter, or every built one."""
    builds = builds_map()
    versions = [v for v in builds if only is None or v in only]
    if only:
        for version in sorted(only - set(builds)):
            print(f"[!] {version}: not built; run lab/fpm/build_php.sh {version}")
    return versions


def up(only: set[str] | None) -> None:
    builds = builds_map()
    versions = select(only)
    if not versions:
        print("[!] nothing to start")
        return
    for version in versions:
        if not os.path.isfile(fpm_bin(version)):
            print(f"[!] {version}: missing {fpm_bin(version)}; run lab/fpm/build_php.sh {version}")
            return
        if not os.path.isfile(NGINX_BIN):
            print(f"[!] missing {NGINX_BIN}; run lab/fpm/build_nginx.sh")
            return
    for version in builds:
        ensure_dirs(version)
    for version in versions:
        write_fpm_conf(version)
    os.makedirs(os.path.join(RUNTIME, "logs"), exist_ok=True)
    # only expose the versions that are running; a later `up --only` rewrites it
    write_nginx_conf(versions)

    busy = []
    for version in versions:
        for port in builds[version]:
            if not port_free(port):
                busy.append(port)
    if busy:
        print(f"[!] ports busy: {busy} (run 'down' first?)")
        return

    for version in versions:
        conf = os.path.join(fpm_prefix(version), "php-fpm.conf")
        print(f"[*] {version}: php-fpm -t", flush=True)
        result = subprocess.run(
            [fpm_bin(version), "-t", "-y", conf, "-c", PHP_INI, "-p", fpm_prefix(version)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(result.stdout, result.stderr)
            print(f"[!] {version}: fpm config test failed")
            return

    print("[*] nginx -t", flush=True)
    result = subprocess.run(
        [NGINX_BIN, "-p", NGINX_PREFIX, "-c", NGINX_CONF, "-t"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(result.stdout, result.stderr)
        print("[!] nginx config test failed")
        return

    for version in versions:
        conf = os.path.join(fpm_prefix(version), "php-fpm.conf")
        print(f"[*] {version}: starting php-fpm", flush=True)
        result = subprocess.run(
            [fpm_bin(version), "-y", conf, "-c", PHP_INI, "-p", fpm_prefix(version), "-D"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(result.stderr)
            print(f"[!] {version}: php-fpm failed to start")
            return
        pidfile = os.path.join(fpm_prefix(version), "logs", "fpm.pid")
        master = read_pid(pidfile)
        chain_http, builder_http, _c, _b = builds[version]
        ok_chain = wait_http(f"http://127.0.0.1:{chain_http}/index.php")
        ok_builder = wait_http(f"http://127.0.0.1:{builder_http}/index.php")
        workers = worker_pids(version, "chain") + worker_pids(version, "builder")
        print(f"    master={master} workers={workers} "
              f"chain={'ok' if ok_chain else 'FAIL'} builder={'ok' if ok_builder else 'FAIL'}")

    print("[*] starting nginx", flush=True)
    result = subprocess.run(
        [NGINX_BIN, "-p", NGINX_PREFIX, "-c", NGINX_CONF],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(result.stderr)
        print("[!] nginx failed to start")
        return
    nginx_pid = read_pid(os.path.join(RUNTIME, "logs", "nginx.pid"))
    print(f"    nginx pid={nginx_pid}")
    for version in versions:
        chain_http, builder_http, _c, _b = builds[version]
        ok = wait_http(f"http://127.0.0.1:{chain_http}/index.php")
        print(f"    {version} front chain:{chain_http}={'ok' if ok else 'FAIL'} "
              f"builder:{builder_http}")
    print("[+] lab up")


def down(only: set[str] | None = None) -> None:
    # nginx fronts every build, so it always goes down; --only restricts the
    # php-fpm masters that are stopped.
    nginx_pid = read_pid(os.path.join(RUNTIME, "logs", "nginx.pid"))
    if nginx_pid:
        subprocess.run([NGINX_BIN, "-p", NGINX_PREFIX, "-c", NGINX_CONF, "-s", "quit"],
                       capture_output=True)
        for _ in range(20):
            if read_pid(os.path.join(RUNTIME, "logs", "nginx.pid")) is None:
                break
            time.sleep(0.2)
        else:
            os.kill(nginx_pid, signal.SIGKILL)
    for version in select(only):
        pidfile = os.path.join(fpm_prefix(version), "logs", "fpm.pid")
        master = read_pid(pidfile)
        if master:
            os.kill(master, signal.SIGTERM)
            for _ in range(30):
                if read_pid(pidfile) is None:
                    break
                time.sleep(0.2)
            else:
                os.kill(master, signal.SIGKILL)
        for pid in worker_pids(version, "chain") + worker_pids(version, "builder"):
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGKILL)
    print("[+] lab down")


def status(only: set[str] | None = None) -> None:
    nginx_pid = read_pid(os.path.join(RUNTIME, "logs", "nginx.pid"))
    print(f"nginx  pid={nginx_pid}")
    builds = builds_map()
    for version in select(only):
        chain_http, builder_http, _c, _b = builds[version]
        pidfile = os.path.join(fpm_prefix(version), "logs", "fpm.pid")
        master = read_pid(pidfile)
        chain = worker_pids(version, "chain")
        builder = worker_pids(version, "builder")
        print(f"{version} fpm master={master} chain_worker={chain} builder_worker={builder} "
              f"http chain=:{chain_http} builder=:{builder_http}")


def smoke(only: set[str] | None = None) -> None:
    ok = True
    builds = builds_map()
    for version in select(only):
        chain_http, builder_http, _c, _b = builds[version]
        for label, port in (("chain", chain_http), ("builder", builder_http)):
            url = f"http://127.0.0.1:{port}/index.php"
            try:
                with urllib.request.urlopen(url, timeout=5) as resp:
                    body = resp.read().decode()
                good = body.strip() == "OK"
            except Exception as exc:
                good = False
                body = str(exc)
            print(f"{version} {label:8} {'ok' if good else 'FAIL'} {body.strip()[:60]}")
            ok = ok and good
            url = f"http://127.0.0.1:{port}/app.php"
            try:
                with urllib.request.urlopen(url, timeout=5) as resp:
                    body = resp.read().decode()
                good = "SESSION_END" in body
            except Exception as exc:
                good = False
                body = str(exc)
            print(f"{version} {label:8} app.php {'ok' if good else 'FAIL'} {body.strip()[:60]}")
            ok = ok and good
    return 0 if ok else 1


def test(only: set[str] | None = None) -> None:
    results = []
    builds = builds_map()
    for version in select(only):
        chain_http, _b, _c, _f = builds[version]
        proof = os.path.join(OUTDIR, "p1")
        with contextlib.suppress(OSError):
            os.unlink(proof)
        cmd = [
            sys.executable, os.path.join(HERE, "php2shell_fpm.py"),
            "chain",
            "--base", f"http://127.0.0.1:{chain_http}",
            "--builder", f"http://127.0.0.1:{builds[version][1]}",
            "--version", version,
            "--command", "id>out/p1",
            "--proof-file", proof,
        ]
        print(f"\n=== {version} chain ===", flush=True)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        print((result.stdout + result.stderr).strip(), flush=True)
        if result.returncode == 0 and os.path.isfile(proof):
            with open(proof, encoding="utf-8") as handle:
                results.append((version, "RCE", handle.read().strip()))
        else:
            results.append((version, f"no RCE (exit {result.returncode})", ""))
    print("\n=== summary ===")
    for version, text, proof in results:
        print(f"  {version:8} {text:24} {proof}")


def ports(only: set[str] | None = None) -> None:
    """Print the port map of the lab."""
    builds = builds_map()
    for version in select(only):
        chain_http, builder_http, chain_fpm, builder_fpm = builds[version]
        print(f"{version:9} chain http :{chain_http} fpm :{chain_fpm}   "
              f"builder http :{builder_http} fpm :{builder_fpm}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Local nginx+FPM PHP2Shell laboratory.")
    parser.add_argument("command",
                        choices=("up", "down", "status", "smoke", "test", "ports"))
    parser.add_argument("--only", default=None, help="comma-separated versions")
    args = parser.parse_args()
    only = set(args.only.split(",")) if args.only else None
    if args.command == "up":
        up(only)
        return 0
    if args.command == "down":
        down(only)
        return 0
    if args.command == "status":
        status(only)
        return 0
    if args.command == "ports":
        ports(only)
        return 0
    if args.command == "smoke":
        return smoke(only)
    test(only)
    return 0


if __name__ == "__main__":
    sys.exit(main())
