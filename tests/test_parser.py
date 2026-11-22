import base64
import json

import pytest

from src.parser import (
    ParseError,
    normalize_proxy,
    parse_by_type,
    parse_uri,
    parse_uri_lines,
)


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def test_vless_reality():
    uri = (
        "vless://11111111-2222-3333-4444-555555555555@example.com:443"
        "?encryption=none&security=reality&sni=cdn.example.com&fp=chrome"
        "&pbk=PUBLICKEY123&sid=abcd&type=tcp&flow=xtls-rprx-vision#reality-node"
    )
    p = parse_uri(uri)
    assert p["type"] == "vless"
    assert p["server"] == "example.com"
    assert p["port"] == 443
    assert p["tls"] is True
    assert p["servername"] == "cdn.example.com"
    assert p["reality-opts"]["public-key"] == "PUBLICKEY123"
    assert p["flow"] == "xtls-rprx-vision"
    assert p["name"] == "reality-node"


def test_vless_ws_tls():
    uri = (
        "vless://UUID@host.example:8443?security=tls&type=ws&path=%2Fws"
        "&host=cdn.host.example&sni=cdn.host.example&allowInsecure=1#ws-node"
    )
    p = parse_uri(uri)
    assert p["network"] == "ws"
    assert p["ws-opts"]["path"] == "/ws"
    assert p["ws-opts"]["headers"]["Host"] == "cdn.host.example"
    assert p["skip-cert-verify"] is True


def test_vmess_base64_json():
    payload = {
        "v": "2",
        "ps": "vmess-node",
        "add": "vm.example.com",
        "port": "443",
        "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "host": "vm.example.com",
        "path": "/ray",
        "tls": "tls",
        "sni": "vm.example.com",
    }
    p = parse_uri("vmess://" + b64(json.dumps(payload)))
    assert p["type"] == "vmess"
    assert p["network"] == "ws"
    assert p["ws-opts"]["path"] == "/ray"
    assert p["alterId"] == 0
    assert p["tls"] is True


def test_trojan_ws():
    uri = "trojan://secret@tj.example.com:443?sni=tj.example.com&type=ws&path=/tj&host=tj.example.com#tj"
    p = parse_uri(uri)
    assert p["type"] == "trojan"
    assert p["password"] == "secret"
    assert p["network"] == "ws"
    assert p["sni"] == "tj.example.com"


def test_ss_sip002_and_legacy():
    sip002 = "ss://" + b64("aes-256-gcm:pass123") + "@ss.example.com:8388#sip002"
    p = parse_uri(sip002)
    assert p["type"] == "ss"
    assert p["cipher"] == "aes-256-gcm"
    assert p["password"] == "pass123"
    assert p["port"] == 8388

    legacy = "ss://" + b64("aes-256-gcm:pass123@ss.example.com:8388") + "#legacy"
    p2 = parse_uri(legacy)
    assert p2["server"] == "ss.example.com"
    assert p2["password"] == "pass123"


def test_hysteria2():
    uri = (
        "hysteria2://pass123@hy.example.com:443?sni=hy.example.com&insecure=1"
        "&obfs=salamander&obfs-password=xyz#hy2"
    )
    p = parse_uri(uri)
    assert p["type"] == "hysteria2"
    assert p["password"] == "pass123"
    assert p["obfs"] == "salamander"
    assert p["skip-cert-verify"] is True


def test_tuic():
    uri = "tuic://uuid-1:pass@tuic.example.com:443?sni=tuic.example.com&alpn=h3&congestion_control=bbr#tuic"
    p = parse_uri(uri)
    assert p["type"] == "tuic"
    assert p["uuid"] == "uuid-1"
    assert p["password"] == "pass"
    assert p["congestion-controller"] == "bbr"


def test_bad_uri_rejected():
    with pytest.raises(ParseError):
        parse_uri("vless://uuid@host:99999?type=tcp")
    with pytest.raises(ParseError):
        parse_uri("ss://" + b64("badcipher:pass") + "@host:80")
    # 未知协议整行被跳过，不抛异常
    assert parse_uri_lines("http://127.0.0.1:8080\nssr://abc\n") == []


def test_clash_yaml_parse():
    text = """
proxies:
  - name: a
    type: vmess
    server: a.example.com
    port: 443
    uuid: u1
    cipher: auto
    alterId: 0
  - name: bad
    type: hysteria
    server: b.example.com
    port: 443
  - name: c
    type: ss
    server: c.example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: p
"""
    kind, nodes = parse_by_type(text, "clash")
    assert kind == "clash"
    assert [n["name"] for n in nodes] == ["a", "c"]


def test_base64_sniff():
    body = " ".join(
        [
            "trojan://p1@a.example.com:443?sni=a.example.com#t1",
            "ss://YWVzLTI1Ni1nY206cGFzcw==@b.example.com:8388#s1",
        ]
    )
    kind, nodes = parse_by_type(b64(body), "auto")
    assert kind == "base64"
    assert len(nodes) == 2


def test_normalize_rejects_unsupported():
    with pytest.raises(ParseError):
        normalize_proxy({"type": "socks5", "server": "x", "port": 1080})
