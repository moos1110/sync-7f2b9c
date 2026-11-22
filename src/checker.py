"""真实代理检测：每个节点独立启动一个 Mihomo 实例，通过 SOCKS5 发真实请求。

不使用"TCP 端口开放"作为判据；只有成功拿到 HTTP 200/204 才算可用。
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import httpx
import yaml

log = logging.getLogger(__name__)

_port_lock = threading.Lock()


@dataclass
class CheckResult:
    ok: bool = False
    latency_ms: int | None = None
    error: str = ""
    country: str | None = None
    attempts: int = 0


@dataclass
class CheckSummary:
    results: dict[str, CheckResult] = field(default_factory=dict)
    checked: int = 0
    succeeded: int = 0

    @property
    def success_rate(self) -> float:
        return (self.succeeded / self.checked) if self.checked else 0.0


def _free_port() -> int:
    with _port_lock:
        for _ in range(32):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            if port > 1024:
                return port
    raise RuntimeError("cannot allocate local port")


def _wait_port(port: int, timeout: float, proc: subprocess.Popen) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), 0.25):
                return True
        except OSError:
            time.sleep(0.05)
    return False


class MihomoChecker:
    def __init__(
        self,
        binary: str,
        *,
        connect_timeout: float = 8.0,
        max_concurrency: int = 20,
        retries: int = 1,
        max_latency_ms: int = 3000,
        test_url: str = "https://www.gstatic.com/generate_204",
        startup_timeout: float = 6.0,
        geo_url: str | None = None,
    ) -> None:
        self.binary = binary
        self.connect_timeout = connect_timeout
        self.max_concurrency = max(1, int(max_concurrency))
        self.retries = max(0, int(retries))
        self.max_latency_ms = int(max_latency_ms)
        self.test_url = test_url
        self.startup_timeout = startup_timeout
        self.geo_url = geo_url

    # ------------------------------------------------------------------ #
    def version(self) -> str | None:
        try:
            out = subprocess.run(
                [self.binary, "-v"], capture_output=True, text=True, timeout=20, check=False
            )
            text = (out.stdout or out.stderr or "").strip()
            return text.splitlines()[0] if text else None
        except (OSError, subprocess.SubprocessError) as exc:
            log.error("mihomo binary not usable: %s", exc)
            return None

    def _write_config(self, workdir: str, proxy: dict, socks_port: int, ctrl_port: int) -> str:
        cfg = {
            "mixed-port": socks_port,
            "external-controller": f"127.0.0.1:{ctrl_port}",
            "allow-lan": False,
            "mode": "rule",
            "log-level": "silent",
            "ipv6": False,
            "dns": {"enable": False},
            "proxies": [proxy],
            "proxy-groups": [{"name": "TEST", "type": "select", "proxies": [proxy["name"]]}],
            "rules": ["MATCH,TEST"],
        }
        path = os.path.join(workdir, "config.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(cfg, fh, allow_unicode=True, sort_keys=False)
        return path

    def _probe(self, socks_port: int) -> tuple[bool, int, str]:
        started = time.perf_counter()
        try:
            with httpx.Client(
                proxy=f"socks5://127.0.0.1:{socks_port}",
                timeout=self.connect_timeout,
                verify=False,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                resp = client.get(self.test_url)
            elapsed = int((time.perf_counter() - started) * 1000)
            if resp.status_code in (200, 204):
                return True, elapsed, ""
            return False, elapsed, f"HTTP {resp.status_code}"
        except Exception as exc:  # noqa: BLE001
            elapsed = int((time.perf_counter() - started) * 1000)
            return False, elapsed, f"{type(exc).__name__}: {exc}"[:160]

    def _geo(self, socks_port: int) -> str | None:
        if not self.geo_url:
            return None
        try:
            with httpx.Client(
                proxy=f"socks5://127.0.0.1:{socks_port}",
                timeout=6.0,
                verify=False,
                trust_env=False,
            ) as client:
                text = client.get(self.geo_url).text
            for line in text.splitlines():
                if line.startswith("loc="):
                    return line.split("=", 1)[1].strip() or None
        except Exception:  # noqa: BLE001
            return None
        return None

    def check_one(self, proxy: dict) -> CheckResult:
        result = CheckResult()
        workdir = tempfile.mkdtemp(prefix="mihomo-")
        socks_port = _free_port()
        ctrl_port = _free_port()
        while ctrl_port == socks_port:
            ctrl_port = _free_port()
        proc: subprocess.Popen | None = None
        try:
            config_path = self._write_config(workdir, proxy, socks_port, ctrl_port)
            proc = subprocess.Popen(
                [self.binary, "-d", workdir, "-f", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            if not _wait_port(socks_port, self.startup_timeout, proc):
                err = ""
                if proc.poll() is not None:
                    try:
                        err = (proc.stderr.read() or "").strip().replace("\n", " ")[:160]
                    except (OSError, ValueError):
                        err = ""
                result.error = f"mihomo start failed {err}".strip()
                return result

            for attempt in range(self.retries + 1):
                result.attempts = attempt + 1
                ok, elapsed, err = self._probe(socks_port)
                if ok:
                    if elapsed > self.max_latency_ms:
                        result.error = f"latency {elapsed}ms > {self.max_latency_ms}ms"
                        result.latency_ms = elapsed
                        return result
                    result.ok = True
                    result.latency_ms = elapsed
                    result.country = self._geo(socks_port)
                    return result
                result.error = err
                if attempt < self.retries:
                    time.sleep(0.4)
            return result
        except Exception as exc:  # noqa: BLE001
            result.error = f"{type(exc).__name__}: {exc}"[:160]
            return result
        finally:
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                if proc.stderr is not None:
                    try:
                        proc.stderr.close()
                    except OSError:
                        pass
            shutil.rmtree(workdir, ignore_errors=True)

    def check_many(self, proxies: list[dict], progress_every: int = 20) -> CheckSummary:
        summary = CheckSummary()
        if not proxies:
            return summary
        total = len(proxies)
        done = 0
        log.info("checking %d nodes with concurrency=%d", total, self.max_concurrency)
        with ThreadPoolExecutor(max_workers=self.max_concurrency) as pool:
            futures = {pool.submit(self.check_one, p): p for p in proxies}
            for future in as_completed(futures):
                proxy = futures[future]
                try:
                    res = future.result()
                except Exception as exc:  # noqa: BLE001
                    res = CheckResult(error=f"{type(exc).__name__}: {exc}"[:160])
                summary.results[proxy["_fp"]] = res
                summary.checked += 1
                if res.ok:
                    summary.succeeded += 1
                done += 1
                if done % progress_every == 0 or done == total:
                    log.info(
                        "progress %d/%d ok=%d (%.1f%%)",
                        done,
                        total,
                        summary.succeeded,
                        100.0 * summary.succeeded / max(done, 1),
                    )
        return summary
