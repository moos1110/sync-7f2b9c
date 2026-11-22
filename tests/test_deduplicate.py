from src.deduplicate import deduplicate, fingerprint, unique_names


def node(**kw):
    base = {
        "name": "n",
        "type": "vless",
        "server": "example.com",
        "port": 443,
        "uuid": "u1",
        "network": "ws",
        "ws-opts": {"path": "/a", "headers": {"Host": "example.com"}},
    }
    base.update(kw)
    return base


def test_same_params_different_name_is_duplicate():
    a = node(name="香港 01")
    b = node(name="HK-Premium")
    kept, removed = deduplicate([a, b])
    assert len(kept) == 1
    assert removed == 1


def test_different_path_not_duplicate():
    a = node(name="a", **{"ws-opts": {"path": "/a"}})
    b = node(name="b", **{"ws-opts": {"path": "/b"}})
    kept, removed = deduplicate([a, b])
    assert len(kept) == 2
    assert removed == 0


def test_different_port_not_duplicate():
    kept, _ = deduplicate([node(name="a"), node(name="b", port=8443)])
    assert len(kept) == 2


def test_fingerprint_stable():
    assert fingerprint(node()) == fingerprint(node(name="other"))


def test_unique_names():
    out = unique_names([node(name="same", port=1), node(name="same", port=2), node(name="")])
    names = [p["name"] for p in out]
    assert names[0] == "same"
    assert names[1] == "same #2"
    assert names[2].startswith("vless-")
