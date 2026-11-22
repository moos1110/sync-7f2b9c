"""排序、Mihomo 配置生成与配置校验。"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

import yaml

from .checker import CheckResult
from .deduplicate import fingerprint

PRIVATE_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]


# --------------------------------------------------------------------------- #
# 排序
# --------------------------------------------------------------------------- #
def success_rate(history: dict, fp: str, default: float) -> float:
    item = history.get(fp) or {}
    ok = int(item.get("ok") or 0)
    fail = int(item.get("fail") or 0)
    if ok + fail == 0:
        return default
    return ok / (ok + fail)


def rank(
    proxies: list[dict],
    results: dict[str, CheckResult],
    history: dict,
    settings: dict,
    max_keep: int,
) -> list[dict]:
    scoring = settings.get("scoring") or {}
    runtime = settings.get("runtime") or {}
    w_lat = float(scoring.get("latency_weight", 0.6))
    w_succ = float(scoring.get("success_weight", 0.4))
    default_sr = float(scoring.get("default_success_rate", 0.5))
    norm = max(float(scoring.get("latency_norm_ms", 3000)), 1.0)

    scored: list[tuple[float, dict]] = []
    for proxy in proxies:
        fp = proxy["_fp"]
        res = results.get(fp)
        if res is None or not res.ok or res.latency_ms is None:
            continue
        sr = success_rate(history, fp, default_sr)
        lat_score = max(0.0, 1.0 - min(res.latency_ms, norm) / norm)
        score = w_succ * sr + w_lat * lat_score
        scored.append((score, {**proxy, "_latency_ms": res.latency_ms, "_score": round(score, 4)}))

    scored.sort(key=lambda item: (-item[0], item[1].get("name", "")))
    kept = [item[1] for item in scored[:max_keep]]
    # 输出顺序按名称稳定排序，避免仅因排序波动产生无意义 diff
    kept.sort(key=lambda p: (str(p.get("name")), fingerprint(p)))
    return kept


# --------------------------------------------------------------------------- #
# 配置生成
# --------------------------------------------------------------------------- #
def _strip_meta(proxy: dict) -> dict:
    return {k: v for k, v in proxy.items() if not k.startswith("_")}


def build_clash_config(proxies: list[dict], settings: dict) -> dict:
    runtime = settings.get("runtime") or {}
    interval = int(runtime.get("health_check_interval", 300))
    tolerance = int(runtime.get("health_check_tolerance", 50))
    test_url = runtime.get("test_url", "https://www.gstatic.com/generate_204")
    names = [p["name"] for p in proxies]

    groups = [
        {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": ["♻️ 自动选择", "🔯 故障转移", *names, "DIRECT"],
        },
        {
            "name": "♻️ 自动选择",
            "type": "url-test",
            "url": test_url,
            "interval": interval,
            "tolerance": tolerance,
            "lazy": False,
            "proxies": names,
        },
        {
            "name": "🔯 故障转移",
            "type": "fallback",
            "url": test_url,
            "interval": interval,
            "lazy": False,
            "proxies": names,
        },
    ]

    rules = [f"IP-CIDR,{cidr},DIRECT,no-resolve" for cidr in PRIVATE_CIDRS]
    rules += [
        "DOMAIN-SUFFIX,local,DIRECT",
        "DOMAIN-SUFFIX,lan,DIRECT",
        "DOMAIN-SUFFIX,cn,DIRECT",
        "MATCH,🚀 节点选择",
    ]

    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "bind-address": "*",
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "unified-delay": True,
        "tcp-concurrent": True,
        "find-process-mode": "off",
        "profile": {"store-selected": True, "store-fake-ip": True},
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["223.5.5.5", "119.29.29.29", "1.1.1.1"],
            "fallback": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
        },
        "proxies": [_strip_meta(p) for p in proxies],
        "proxy-groups": groups,
        "rules": rules,
    }


def build_proxies_doc(proxies: list[dict]) -> dict:
    return {"proxies": [_strip_meta(p) for p in proxies]}


def dump_yaml(data: dict) -> str:
    header = "# 由 auto-free-proxy-pool 自动生成，请勿手工修改\n"
    return header + yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=4096)


# --------------------------------------------------------------------------- #
# 校验与落盘
# --------------------------------------------------------------------------- #
def validate_config(binary: str, config_path: str) -> tuple[bool, str]:
    workdir = tempfile.mkdtemp(prefix="mihomo-validate-")
    try:
        proc = subprocess.run(
            [binary, "-t", "-d", workdir, "-f", config_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=120,
            check=False,
        )
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        ok = proc.returncode == 0 and "successful" in out.lower()
        return ok, out[-800:]
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def write_outputs(out_dir: str, clash_text: str, proxies_text: str, report: dict, clash_name: str, proxies_name: str, report_name: str) -> None:
    """先写临时文件，全部成功后再原子替换，避免半成品落盘。"""
    os.makedirs(out_dir, exist_ok=True)
    tmp_dir = tempfile.mkdtemp(prefix="out-", dir=os.path.dirname(os.path.abspath(out_dir)) or None)
    try:
        staged = {
            clash_name: clash_text,
            proxies_name: proxies_text,
            report_name: json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        }
        for name, content in staged.items():
            with open(os.path.join(tmp_dir, name), "w", encoding="utf-8") as fh:
                fh.write(content)
        for name in staged:
            os.replace(os.path.join(tmp_dir, name), os.path.join(out_dir, name))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
