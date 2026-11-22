from src.checker import CheckResult
from src.generator import build_clash_config, build_proxies_doc, dump_yaml, rank

SETTINGS = {
    "runtime": {"health_check_interval": 300, "health_check_tolerance": 50,
                "test_url": "https://www.gstatic.com/generate_204"},
    "scoring": {"latency_weight": 0.6, "success_weight": 0.4,
                "default_success_rate": 0.5, "latency_norm_ms": 3000},
}


def make_nodes():
    return [
        {"_fp": "fp1", "name": "node-1", "type": "vless", "server": "a.com", "port": 443, "uuid": "u"},
        {"_fp": "fp2", "name": "node-2", "type": "trojan", "server": "b.com", "port": 443, "password": "p"},
    ]


def test_rank_drops_failed_and_sorts_by_score():
    nodes = make_nodes()
    results = {
        "fp1": CheckResult(ok=True, latency_ms=200),
        "fp2": CheckResult(ok=False, error="timeout"),
    }
    kept = rank(nodes, results, {}, SETTINGS, max_keep=10)
    assert [n["name"] for n in kept] == ["node-1"]
    assert kept[0]["_latency_ms"] == 200


def test_rank_respects_max_keep():
    nodes = [
        {"_fp": f"fp{i}", "name": f"n{i}", "type": "ss", "server": "x", "port": 1 + i,
         "cipher": "aes-256-gcm", "password": "p"}
        for i in range(10)
    ]
    results = {f"fp{i}": CheckResult(ok=True, latency_ms=100 + i) for i in range(10)}
    kept = rank(nodes, results, {}, SETTINGS, max_keep=3)
    assert len(kept) == 3


def test_generated_config_groups():
    nodes = make_nodes()
    cfg = build_clash_config(nodes, SETTINGS)
    groups = {g["name"]: g for g in cfg["proxy-groups"]}
    assert groups["♻️ 自动选择"]["type"] == "url-test"
    assert groups["♻️ 自动选择"]["interval"] == 300
    assert groups["🔯 故障转移"]["type"] == "fallback"
    # 自动分组绝不含 DIRECT，避免节点全失效时静默回退直连
    assert "DIRECT" not in groups["♻️ 自动选择"]["proxies"]
    assert "DIRECT" not in groups["🔯 故障转移"]["proxies"]
    # 手动选择里允许显式选 DIRECT
    assert groups["🚀 节点选择"]["proxies"][-1] == "DIRECT"


def test_meta_fields_stripped():
    nodes = make_nodes()
    cfg = build_clash_config(nodes, SETTINGS)
    for proxy in cfg["proxies"]:
        assert not any(k.startswith("_") for k in proxy)
    doc = build_proxies_doc(nodes)
    assert "proxies" in doc
    assert all("_fp" not in p for p in doc["proxies"])


def test_dump_yaml_is_parseable():
    import yaml

    text = dump_yaml(build_clash_config(make_nodes(), SETTINGS))
    data = yaml.safe_load(text)
    assert len(data["proxies"]) == 2
    assert data["rules"][-1] == "MATCH,🚀 节点选择"
