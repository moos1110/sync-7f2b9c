"""去重与名称规范化：按真实连接参数建立指纹，不依赖节点名。"""

from __future__ import annotations

import hashlib
import json
import re

IDENTITY_FIELDS = (
    "type",
    "server",
    "port",
    "uuid",
    "password",
    "cipher",
    "network",
    "flow",
    "servername",
    "sni",
    "obfs",
    "plugin",
)

_DUP_SUFFIX = re.compile(r"\s*\(\d+\)$")


def fingerprint(proxy: dict) -> str:
    ident = {}
    for key in IDENTITY_FIELDS:
        val = proxy.get(key)
        if val in (None, ""):
            continue
        ident[key] = str(val).strip().lower() if key in ("server", "network", "cipher") else str(val).strip()

    # 传输层的真实差异参数
    for key in ("ws-opts", "grpc-opts", "h2-opts", "reality-opts", "plugin-opts"):
        opts = proxy.get(key)
        if isinstance(opts, dict) and opts:
            ident[key] = json.dumps(opts, sort_keys=True, ensure_ascii=False)

    blob = json.dumps(ident, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]


def deduplicate(proxies: list[dict]) -> tuple[list[dict], int]:
    """返回 (去重后列表, 被移除的重复数)。保留先出现的节点。"""
    seen: set[str] = set()
    kept: list[dict] = []
    for proxy in proxies:
        fp = fingerprint(proxy)
        if fp in seen:
            continue
        seen.add(fp)
        proxy = dict(proxy)
        proxy["_fp"] = fp
        kept.append(proxy)
    return kept, len(proxies) - len(kept)


def unique_names(proxies: list[dict]) -> list[dict]:
    """保证节点名唯一且非空，重名追加序号，避免配置行为歧义。"""
    used: dict[str, int] = {}
    out: list[dict] = []
    for proxy in proxies:
        proxy = dict(proxy)
        base = _DUP_SUFFIX.sub("", str(proxy.get("name") or "").strip())
        if not base:
            base = f"{proxy.get('type')}-{proxy.get('server')}:{proxy.get('port')}"
        base = base[:40]
        count = used.get(base, 0)
        used[base] = count + 1
        proxy["name"] = base if count == 0 else f"{base} #{count + 1}"
        out.append(proxy)
    return out
