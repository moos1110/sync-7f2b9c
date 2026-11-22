"""节点解析：Clash YAML / 标准代理 URI / Base64 列表 -> 统一 Mihomo proxy 字典。"""

from __future__ import annotations

import base64
import binascii
import json
import re
from urllib.parse import parse_qs, unquote, urlsplit

import yaml

SUPPORTED_TYPES = {"vless", "vmess", "trojan", "ss", "hysteria2", "tuic"}

SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "chacha20-ietf", "xchacha20",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "none",
}

_NAME_BAD = re.compile(r"[\x00-\x1f\x7f]+")


class ParseError(ValueError):
    """单个节点解析失败。"""


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #
def b64decode_any(data: str) -> str:
    """宽松 base64 解码：兼容 urlsafe、缺失填充、空白换行。"""
    s = re.sub(r"\s+", "", data or "")
    if not s:
        raise ParseError("empty base64")
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=False).decode("utf-8", "ignore")
    except (binascii.Error, ValueError) as exc:
        raise ParseError(f"bad base64: {exc}") from exc


def _clean_name(name: str | None, fallback: str) -> str:
    if name:
        cleaned = _NAME_BAD.sub("", unquote(str(name))).strip()
        cleaned = re.sub(r"\s+", " ", cleaned)
        if cleaned:
            return cleaned[:48]
    return fallback


def _split_hostport(value: str) -> tuple[str, int]:
    value = (value or "").strip().strip("/")
    if not value:
        raise ParseError("empty host")
    if value.startswith("["):
        host, _, rest = value.partition("]")
        host, port = host[1:], rest.lstrip(":")
    elif value.count(":") > 1:
        host, _, port = value.rpartition(":")
    else:
        host, _, port = value.partition(":")
    host = host.strip()
    if not host:
        raise ParseError("empty host")
    try:
        port_i = int(str(port).strip())
    except (TypeError, ValueError) as exc:
        raise ParseError(f"bad port: {port!r}") from exc
    if not 1 <= port_i <= 65535:
        raise ParseError(f"port out of range: {port_i}")
    return host, port_i


def _truthy(value: str | None) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _first(params: dict[str, list[str]], *keys: str) -> str | None:
    for key in keys:
        got = params.get(key)
        if got:
            val = str(got[0]).strip()
            if val:
                return val
    return None


def _transport(net: str, params: dict[str, list[str]], host_fallback: str | None = None):
    """构造 ws / grpc / h2 传输参数。"""
    net = (net or "tcp").lower()
    if net in ("ws", "httpupgrade"):
        path = _first(params, "path") or "/"
        if not path.startswith("/"):
            path = "/" + path
        host = _first(params, "host", "sni") or host_fallback
        opts: dict = {"path": path}
        if host:
            opts["headers"] = {"Host": host}
        return "ws", {"ws-opts": opts}
    if net == "grpc":
        service = _first(params, "serviceName", "servicename", "path") or ""
        return "grpc", {"grpc-opts": {"grpc-service-name": service.lstrip("/")}}
    if net in ("h2", "http"):
        host = _first(params, "host", "sni") or host_fallback
        opts: dict = {"path": _first(params, "path") or "/"}
        if host:
            hosts = [h.strip() for h in host.split(",") if h.strip()]
            if hosts:
                opts["host"] = hosts
        return "h2", {"h2-opts": opts}
    return "tcp", {}


def _tls_block(proxy: dict, params: dict[str, list[str]], sni: str | None, sni_key: str = "servername") -> None:
    proxy["tls"] = True
    if sni:
        proxy[sni_key] = sni
    alpn = _first(params, "alpn")
    if alpn:
        proxy["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
    fp = _first(params, "fp", "fingerprint")
    if fp:
        proxy["client-fingerprint"] = fp
    if _truthy(_first(params, "allowInsecure", "insecure", "skip-cert-verify")):
        proxy["skip-cert-verify"] = True


# --------------------------------------------------------------------------- #
# 各协议 URI 解析
# --------------------------------------------------------------------------- #
def parse_vless(uri: str) -> dict:
    sp = urlsplit(uri)
    if not sp.hostname or not sp.port:
        raise ParseError("vless: missing host/port")
    uuid = unquote(sp.username or "").strip()
    if not uuid:
        raise ParseError("vless: missing uuid")
    params = parse_qs(sp.query)
    proxy: dict = {
        "name": _clean_name(sp.fragment, f"vless-{sp.hostname}:{sp.port}"),
        "type": "vless",
        "server": sp.hostname,
        "port": int(sp.port),
        "uuid": uuid,
        "udp": True,
    }
    flow = _first(params, "flow")
    if flow:
        proxy["flow"] = flow

    security = (_first(params, "security") or "none").lower()
    sni = _first(params, "sni", "peer", "host")
    if security in ("tls", "xtls", "reality"):
        _tls_block(proxy, params, sni)
        if security == "reality":
            pbk = _first(params, "pbk", "public-key")
            if not pbk:
                proxy.pop("tls", None)
                raise ParseError("vless: reality without public-key")
            proxy["reality-opts"] = {
                "public-key": pbk,
                "short-id": _first(params, "sid") or "",
            }

    net, extra = _transport(_first(params, "type", "network") or "tcp", params, sni)
    proxy["network"] = net
    proxy.update(extra)
    return proxy


def parse_vmess(uri: str) -> dict:
    body = uri.split("://", 1)[1]
    try:
        raw = json.loads(b64decode_any(body))
        if not isinstance(raw, dict):
            raise ParseError("vmess: payload is not an object")
    except (ParseError, json.JSONDecodeError):
        # 少数非标准 vmess://uuid@host:port 形式
        return parse_vless("vless://" + body).copy() | {"type": "vmess"}

    server = str(raw.get("add") or "").strip()
    if not server:
        raise ParseError("vmess: missing add")
    try:
        port = int(str(raw.get("port")).strip())
    except (TypeError, ValueError) as exc:
        raise ParseError("vmess: bad port") from exc
    if not 1 <= port <= 65535:
        raise ParseError("vmess: port out of range")
    uuid = str(raw.get("id") or "").strip()
    if not uuid:
        raise ParseError("vmess: missing id")

    name = _clean_name(raw.get("ps"), f"vmess-{server}:{port}")
    try:
        alter_id = int(raw.get("aid") or 0)
    except (TypeError, ValueError):
        alter_id = 0

    proxy: dict = {
        "name": name,
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alterId": alter_id,
        "cipher": str(raw.get("scy") or "auto") or "auto",
        "udp": True,
    }
    tls = str(raw.get("tls") or "").strip().lower()
    host = str(raw.get("host") or "").strip()
    sni = str(raw.get("sni") or "").strip()
    if tls in ("tls", "reality", "xtls"):
        proxy["tls"] = True
        if sni or host:
            proxy["servername"] = sni or host
        if str(raw.get("skip-cert-verify") or "").lower() in ("1", "true"):
            proxy["skip-cert-verify"] = True
        alpn = str(raw.get("alpn") or "").strip()
        if alpn:
            proxy["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
        fp = str(raw.get("fp") or "").strip()
        if fp:
            proxy["client-fingerprint"] = fp

    net = str(raw.get("net") or "tcp").strip().lower()
    path = str(raw.get("path") or "/").strip() or "/"
    if net in ("ws", "httpupgrade"):
        opts: dict = {"path": path if path.startswith("/") else "/" + path}
        if host:
            opts["headers"] = {"Host": host}
        proxy["network"] = "ws"
        proxy["ws-opts"] = opts
    elif net == "grpc":
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": path.lstrip("/")}
    elif net in ("h2", "http"):
        proxy["network"] = "h2"
        h2: dict = {"path": path}
        if host:
            h2["host"] = [h.strip() for h in host.split(",") if h.strip()]
        proxy["h2-opts"] = h2
    else:
        proxy["network"] = "tcp"
    return proxy


def parse_trojan(uri: str) -> dict:
    sp = urlsplit(uri)
    if not sp.hostname or not sp.port:
        raise ParseError("trojan: missing host/port")
    password = unquote(sp.username or "").strip()
    if not password:
        raise ParseError("trojan: missing password")
    params = parse_qs(sp.query)
    proxy: dict = {
        "name": _clean_name(sp.fragment, f"trojan-{sp.hostname}:{sp.port}"),
        "type": "trojan",
        "server": sp.hostname,
        "port": int(sp.port),
        "password": password,
        "udp": True,
    }
    sni = _first(params, "sni", "peer", "host")
    if sni:
        proxy["sni"] = sni
    if _truthy(_first(params, "allowInsecure", "insecure")):
        proxy["skip-cert-verify"] = True
    alpn = _first(params, "alpn")
    if alpn:
        proxy["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
    fp = _first(params, "fp", "fingerprint")
    if fp:
        proxy["client-fingerprint"] = fp
    net, extra = _transport(_first(params, "type", "network") or "tcp", params, sni)
    if net != "tcp":
        proxy["network"] = net
        proxy.update(extra)
    return proxy


def _ss_plugin(opts: dict, plugin_spec: str) -> None:
    parts = [p for p in plugin_spec.split(";") if p.strip()]
    if not parts:
        return
    kind = parts[0].strip().lower()
    kv: dict[str, str] = {}
    for part in parts[1:]:
        key, _, val = part.partition("=")
        kv[key.strip().lower()] = val.strip()
    if kind in ("obfs-local", "simple-obfs", "obfs"):
        opts["plugin"] = "obfs"
        opts["plugin-opts"] = {"mode": kv.get("obfs", "http"), "host": kv.get("obfs-host", "")}
    elif kind == "v2ray-plugin":
        opts["plugin"] = "v2ray-plugin"
        popts: dict = {"mode": kv.get("mode", "websocket")}
        if kv.get("host"):
            popts["host"] = kv["host"]
        if kv.get("path"):
            popts["path"] = kv["path"]
        if "tls" in kv:
            popts["tls"] = True
        opts["plugin-opts"] = popts
    else:
        raise ParseError(f"ss: unsupported plugin {kind}")


def parse_ss(uri: str) -> dict:
    body = uri.split("://", 1)[1]
    body, _, frag = body.partition("#")
    body, _, query = body.partition("?")
    params = parse_qs(query)

    if "@" in body:
        userinfo, _, hostport = body.rpartition("@")
        if ":" not in userinfo:
            userinfo = b64decode_any(userinfo)
    else:
        decoded = b64decode_any(body)
        userinfo, _, hostport = decoded.rpartition("@")
        if not hostport:
            raise ParseError("ss: missing host/port")
    method, sep, password = userinfo.partition(":")
    if not sep or not method or not password:
        raise ParseError("ss: bad userinfo")
    method = method.strip().lower()
    if method not in SS_CIPHERS:
        raise ParseError(f"ss: unsupported cipher {method}")
    host, port = _split_hostport(hostport)
    proxy: dict = {
        "name": _clean_name(frag, f"ss-{host}:{port}"),
        "type": "ss",
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
        "udp": True,
    }
    plugin_spec = _first(params, "plugin")
    if plugin_spec:
        _ss_plugin(proxy, unquote(plugin_spec))
    return proxy


def parse_hysteria2(uri: str) -> dict:
    sp = urlsplit(uri)
    if not sp.hostname or not sp.port:
        raise ParseError("hysteria2: missing host/port")
    params = parse_qs(sp.query)
    password = unquote(sp.username or "").strip() or (_first(params, "auth", "password") or "")
    if not password:
        raise ParseError("hysteria2: missing password")
    proxy: dict = {
        "name": _clean_name(sp.fragment, f"hy2-{sp.hostname}:{sp.port}"),
        "type": "hysteria2",
        "server": sp.hostname,
        "port": int(sp.port),
        "password": password,
        "udp": True,
    }
    sni = _first(params, "sni", "peer")
    if sni:
        proxy["sni"] = sni
    if _truthy(_first(params, "insecure", "allowInsecure")):
        proxy["skip-cert-verify"] = True
    obfs = _first(params, "obfs")
    if obfs and obfs.lower() != "none":
        proxy["obfs"] = obfs
        obfs_pwd = _first(params, "obfs-password", "obfsParam")
        if obfs_pwd:
            proxy["obfs-password"] = obfs_pwd
    for key, field in (("up", "up"), ("down", "down"), ("upmbps", "up"), ("downmbps", "down")):
        val = _first(params, key)
        if val:
            proxy[field] = val if not val.isdigit() else f"{val} Mbps"
    return proxy


def parse_tuic(uri: str) -> dict:
    sp = urlsplit(uri)
    if not sp.hostname or not sp.port:
        raise ParseError("tuic: missing host/port")
    uuid = unquote(sp.username or "").strip()
    password = unquote(sp.password or "").strip()
    params = parse_qs(sp.query)
    if not uuid:
        raise ParseError("tuic: missing uuid")
    if not password:
        password = _first(params, "password") or ""
    if not password:
        raise ParseError("tuic: missing password")
    proxy: dict = {
        "name": _clean_name(sp.fragment, f"tuic-{sp.hostname}:{sp.port}"),
        "type": "tuic",
        "server": sp.hostname,
        "port": int(sp.port),
        "uuid": uuid,
        "password": password,
        "udp": True,
    }
    sni = _first(params, "sni", "peer")
    if sni:
        proxy["sni"] = sni
    alpn = _first(params, "alpn")
    if alpn:
        proxy["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
    cc = _first(params, "congestion_control", "congestion-controller", "congestion")
    if cc:
        proxy["congestion-controller"] = cc
    urm = _first(params, "udp_relay_mode", "udp-relay-mode")
    if urm:
        proxy["udp-relay-mode"] = urm
    if _truthy(_first(params, "allow_insecure", "allowInsecure", "insecure")):
        proxy["skip-cert-verify"] = True
    return proxy


URI_PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_ss,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "tuic": parse_tuic,
}


def parse_uri(line: str) -> dict:
    line = line.strip()
    if not line or line.startswith("#"):
        raise ParseError("empty line")
    scheme = line.split("://", 1)[0].strip().lower() if "://" in line else ""
    handler = URI_PARSERS.get(scheme)
    if handler is None:
        raise ParseError(f"unsupported scheme: {scheme or '-'}")
    try:
        proxy = handler(line)
    except ParseError:
        raise
    except ValueError as exc:  # urlsplit 对越界端口等会抛 ValueError
        raise ParseError(str(exc)) from exc
    return normalize_proxy(proxy)


# --------------------------------------------------------------------------- #
# Clash / Mihomo YAML 解析
# --------------------------------------------------------------------------- #
def normalize_proxy(raw: dict) -> dict:
    """校验并规范化 Clash 风格 proxy 字典。"""
    if not isinstance(raw, dict):
        raise ParseError("proxy is not a mapping")
    ptype = str(raw.get("type") or "").strip().lower()
    if ptype == "hy2":
        ptype = "hysteria2"
    if ptype not in SUPPORTED_TYPES:
        raise ParseError(f"unsupported type: {ptype or '-'}")

    server = str(raw.get("server") or raw.get("address") or "").strip()
    if not server:
        raise ParseError("missing server")
    try:
        port = int(str(raw.get("port")).strip())
    except (TypeError, ValueError) as exc:
        raise ParseError("bad port") from exc
    if not 1 <= port <= 65535:
        raise ParseError("port out of range")

    proxy = dict(raw)
    proxy["type"] = ptype
    proxy["server"] = server
    proxy["port"] = port
    proxy["name"] = _clean_name(proxy.get("name"), f"{ptype}-{server}:{port}")
    proxy.pop("address", None)

    if ptype in ("vless", "vmess"):
        if not str(proxy.get("uuid") or "").strip():
            raise ParseError(f"{ptype}: missing uuid")
        if ptype == "vmess":
            proxy["alterId"] = int(proxy.get("alterId") or proxy.get("alterid") or 0)
            proxy.setdefault("cipher", "auto")
            proxy.pop("alterid", None)
    elif ptype == "trojan":
        if not str(proxy.get("password") or "").strip():
            raise ParseError("trojan: missing password")
    elif ptype == "ss":
        cipher = str(proxy.get("cipher") or "").strip().lower()
        if cipher not in SS_CIPHERS:
            raise ParseError(f"ss: unsupported cipher {cipher or '-'}")
        proxy["cipher"] = cipher
        if not str(proxy.get("password") or "").strip():
            raise ParseError("ss: missing password")
    elif ptype in ("hysteria2", "tuic"):
        if not str(proxy.get("password") or "").strip():
            raise ParseError(f"{ptype}: missing password")
        if ptype == "tuic" and not str(proxy.get("uuid") or "").strip():
            raise ParseError("tuic: missing uuid")

    for key in ("udp", "tls", "skip-cert-verify"):
        if key in proxy and isinstance(proxy[key], str):
            proxy[key] = _truthy(proxy[key])
    proxy.setdefault("udp", True)
    if proxy.get("network") in (None, ""):
        proxy.pop("network", None)
    if proxy.get("servername") and not str(proxy["servername"]).strip():
        proxy.pop("servername")
    return proxy


def parse_clash_yaml(text: str) -> list[dict]:
    data = yaml.safe_load(text)
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("proxies") or data.get("Proxy") or []
    else:
        raise ParseError("yaml: unexpected root type")
    if not isinstance(items, list):
        raise ParseError("yaml: proxies is not a list")
    out = []
    for item in items:
        try:
            out.append(normalize_proxy(item))
        except (ParseError, TypeError, ValueError):
            continue
    return out


def parse_uri_lines(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # 兼容空格/制表符拼接成一行的列表
        tokens = [line]
        if line.count("://") > 1:
            tokens = [tok for tok in re.split(r"\s+", line) if "://" in tok]
        for token in tokens:
            try:
                out.append(parse_uri(token))
            except ParseError:
                continue
    return out


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
B64_ONLY = re.compile(r"^[A-Za-z0-9+/=_\-\s]+$")


def sniff_and_parse(text: str) -> tuple[str, list[dict]]:
    """返回 (识别到的格式, 节点列表)。"""
    if not text or not text.strip():
        raise ParseError("empty content")
    head = text.lstrip()[:4096]
    if "proxies:" in head or head.startswith("Proxy:") or head.startswith("- {"):
        return "clash", parse_clash_yaml(text)
    if "://" in text:
        return "uri", parse_uri_lines(text)
    if B64_ONLY.match(text.strip()[:4096]):
        decoded = b64decode_any(text)
        if "://" in decoded:
            return "base64", parse_uri_lines(decoded)
        raise ParseError("base64 decoded without uris")
    raise ParseError("unrecognized content")


def parse_by_type(text: str, kind: str = "auto") -> tuple[str, list[dict]]:
    kind = (kind or "auto").lower()
    if kind == "auto":
        return sniff_and_parse(text)
    if kind == "clash":
        return "clash", parse_clash_yaml(text)
    if kind == "uri":
        return "uri", parse_uri_lines(text)
    if kind == "base64":
        # 容错：标为 base64 但实际是明文 URI 列表时自动回退
        try:
            decoded = b64decode_any(text)
        except ParseError:
            decoded = ""
        if "://" in decoded:
            return "base64", parse_uri_lines(decoded)
        if "://" in text:
            return "uri", parse_uri_lines(text)
        raise ParseError("base64 source contains no uris")
    raise ParseError(f"unknown source type: {kind}")
