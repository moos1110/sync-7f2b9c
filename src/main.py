"""编排入口：采集 -> 解析 -> 去重 -> 检测 -> 排序 -> 生成 -> 校验 -> 落盘。"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time

import yaml

from .checker import MihomoChecker
from .collector import fetch_all, load_sources
from .deduplicate import deduplicate, unique_names
from .generator import (
    build_clash_config,
    build_proxies_doc,
    dump_yaml,
    rank,
    success_rate,
    utc_now,
    validate_config,
    write_outputs,
)
from .parser import ParseError, parse_by_type

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("main")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _abs(path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(ROOT, path)


def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def save_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def pick_candidates(proxies: list[dict], history: dict, limit: int, settings: dict) -> list[dict]:
    if limit <= 0 or len(proxies) <= limit:
        return proxies
    default_sr = float((settings.get("scoring") or {}).get("default_success_rate", 0.5))
    seed = utc_now()[:13]  # 每 4 小时轮换一次抽样顺序

    def key(proxy: dict):
        fp = proxy["_fp"]
        item = history.get(fp) or {}
        total = int(item.get("ok") or 0) + int(item.get("fail") or 0)
        has_history = 1 if total > 0 else 0
        sr = success_rate(history, fp, default_sr)
        rotation = hashlib.sha1(f"{fp}:{seed}".encode()).hexdigest()
        return (-has_history, -sr, rotation)

    picked = sorted(proxies, key=key)[:limit]
    log.info("candidate cap: %d -> %d (history-aware, rotating)", len(proxies), len(picked))
    return picked


def write_report_only(out_dir: str, report: dict) -> None:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "report.json")
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="personal proxy pool updater")
    parser.add_argument("--settings", default="config/settings.yaml")
    parser.add_argument("--sources", default="config/sources.yaml")
    parser.add_argument("--dry-run", action="store_true", help="跳过真实代理检测")
    parser.add_argument("--limit", type=int, default=0, help="覆盖最大候选数（调试用）")
    parser.add_argument("--skip-validate", action="store_true")
    args = parser.parse_args(argv)

    started = time.time()
    settings = load_yaml(_abs(args.settings))
    runtime = settings.get("runtime") or {}
    output_cfg = settings.get("output") or {}
    out_dir = _abs(output_cfg.get("dir", "output"))
    clash_name = output_cfg.get("clash", "clash.yaml")
    proxies_name = output_cfg.get("proxies", "proxies.yaml")
    report_name = output_cfg.get("report", "report.json")

    history_path = _abs(runtime.get("history_file", "state/history.json"))
    state_path = _abs("state/sources.json")
    history = load_json(history_path, {})
    source_state = load_json(state_path, {})

    report: dict = {
        "status": "failed",
        "started_at": utc_now(),
        "finished_at": None,
        "duration_sec": None,
        "sources_total": 0,
        "sources_ok": 0,
        "fetched_nodes": 0,
        "parsed_nodes": 0,
        "deduped_nodes": 0,
        "duplicates_removed": 0,
        "candidates": 0,
        "checked_nodes": 0,
        "alive_nodes": 0,
        "kept_nodes": 0,
        "avg_latency_ms": None,
        "protocols": {},
        "config_valid": False,
        "mihomo_version": None,
        "failure_reasons": [],
        "sources": [],
        "proxies_hash": None,
    }

    bin_path = os.environ.get("MIHOMO_BIN") or "mihomo"

    try:
        specs = load_sources(_abs(args.sources))
        report["sources_total"] = len([s for s in specs if s.enabled])
        log.info("sources: %d enabled", report["sources_total"])

        fetched = fetch_all(specs, source_state.get("last_fetch") or {})
        report["sources"] = fetched.summary()
        report["sources_ok"] = fetched.ok_count

        last_fetch = source_state.get("last_fetch") or {}
        raw_nodes: list[dict] = []
        per_source: dict[str, int] = {}
        for res in fetched.results:
            if not res.ok:
                continue
            last_fetch[res.source.name] = time.time()
            try:
                kind, nodes = parse_by_type(res.content, res.source.type)
                for node in nodes:
                    node["_source"] = res.source.name
                    raw_nodes.append(node)
                per_source[res.source.name] = len(nodes)
                log.info("parsed %-28s %-6s nodes=%d", res.source.name, kind, len(nodes))
            except ParseError as exc:
                log.warning("parse failed %s: %s", res.source.name, exc)
                report["failure_reasons"].append(f"parse:{res.source.name}:{exc}")
            except Exception as exc:  # noqa: BLE001
                log.warning("parse crashed %s: %s", res.source.name, exc)
                report["failure_reasons"].append(f"parse:{res.source.name}:{type(exc).__name__}")

        report["fetched_nodes"] = len(raw_nodes)
        if not raw_nodes:
            report["failure_reasons"].append("no nodes collected from any source")
            report["finished_at"] = utc_now()
            report["duration_sec"] = round(time.time() - started, 1)
            write_report_only(out_dir, report)
            log.error("no nodes collected; keeping previous outputs untouched")
            return 3

        parsed = [n for n in raw_nodes if n.get("server") and n.get("port")]
        report["parsed_nodes"] = len(parsed)
        deduped, removed = deduplicate(parsed)
        deduped = unique_names(deduped)
        report["deduped_nodes"] = len(deduped)
        report["duplicates_removed"] = removed
        log.info("parsed=%d deduped=%d removed=%d", len(parsed), len(deduped), removed)

        cap = args.limit or int(runtime.get("max_candidates", 300))
        candidates = pick_candidates(deduped, history, cap, settings)
        report["candidates"] = len(candidates)

        if args.dry_run:
            log.warning("dry-run: skipping real proxy checks")
            results = {}
        else:
            checker = MihomoChecker(
                bin_path,
                connect_timeout=float(runtime.get("connect_timeout", 8)),
                max_concurrency=int(runtime.get("max_concurrency", 20)),
                retries=int(runtime.get("retries", 1)),
                max_latency_ms=int(runtime.get("max_latency_ms", 3000)),
                test_url=runtime.get("test_url", "https://www.gstatic.com/generate_204"),
                startup_timeout=float(runtime.get("startup_timeout", 6)),
                geo_url=((settings.get("geo") or {}).get("url") if (settings.get("geo") or {}).get("enabled") else None),
            )
            version = checker.version()
            report["mihomo_version"] = version
            if not version:
                report["failure_reasons"].append("mihomo binary unavailable")
                raise RuntimeError(f"mihomo binary not usable: {bin_path}")
            log.info("mihomo: %s", version)
            summary = checker.check_many(candidates)
            results = summary.results
            report["checked_nodes"] = summary.checked
            report["alive_nodes"] = summary.succeeded
            log.info("alive %d/%d", summary.succeeded, summary.checked)

            # 更新历史成绩
            now = time.time()
            for fp, res in results.items():
                item = history.setdefault(fp, {"ok": 0, "fail": 0})
                if res.ok:
                    item["ok"] = int(item.get("ok") or 0) + 1
                    item["last_latency"] = res.latency_ms
                    item["last_ok_at"] = int(now)
                    if res.country:
                        item["country"] = res.country
                else:
                    item["fail"] = int(item.get("fail") or 0)
                    item["fail"] += 1

        max_keep = int(runtime.get("max_keep", 100))
        kept = rank(deduped, results, history, settings, max_keep) if results else []
        if args.dry_run:
            kept = deduped[:max_keep]
        report["kept_nodes"] = len(kept)
        if kept:
            latencies = [k.get("_latency_ms") for k in kept if k.get("_latency_ms")]
            report["avg_latency_ms"] = round(sum(latencies) / len(latencies)) if latencies else None
            proto: dict[str, int] = {}
            for node in kept:
                proto[node["type"]] = proto.get(node["type"], 0) + 1
            report["protocols"] = proto

        min_valid = int(runtime.get("min_valid_nodes", 5))
        if not args.dry_run and len(kept) < min_valid:
            report["failure_reasons"].append(
                f"kept_nodes {len(kept)} < min_valid_nodes {min_valid}"
            )
            report["finished_at"] = utc_now()
            report["duration_sec"] = round(time.time() - started, 1)
            write_report_only(out_dir, report)
            log.error("safety gate: only %d valid nodes, previous outputs preserved", len(kept))
            return 3

        clash_cfg = build_clash_config(kept, settings)
        proxies_cfg = build_proxies_doc(kept)
        clash_text = dump_yaml(clash_cfg)
        proxies_text = dump_yaml(proxies_cfg)
        report["proxies_hash"] = hashlib.sha1(proxies_text.encode("utf-8")).hexdigest()[:16]

        if args.dry_run or args.skip_validate:
            report["config_valid"] = True
            report["failure_reasons"].append("validation skipped (dry-run)")
        else:
            validate_dir = os.path.join(out_dir)
            os.makedirs(validate_dir, exist_ok=True)
            tmp_path = os.path.join(validate_dir, f".{clash_name}.tmp")
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(clash_text)
            ok, msg = validate_config(bin_path, tmp_path)
            os.remove(tmp_path)
            report["config_valid"] = ok
            if not ok:
                report["failure_reasons"].append(f"mihomo config test failed: {msg}")
                report["finished_at"] = utc_now()
                report["duration_sec"] = round(time.time() - started, 1)
                write_report_only(out_dir, report)
                log.error("config validation failed, previous outputs preserved:\n%s", msg)
                return 3
            log.info("config validation: OK")

        report["status"] = "ok"
        report["finished_at"] = utc_now()
        report["duration_sec"] = round(time.time() - started, 1)
        write_outputs(out_dir, clash_text, proxies_text, report, clash_name, proxies_name, report_name)

        # 历史只保留最近有效节点，避免无限膨胀
        keep_fps = {p["_fp"] for p in kept}
        pruned = {fp: item for fp, item in history.items() if fp in keep_fps or int(item.get("last_ok_at") or 0) > time.time() - 86400 * 7}
        if len(pruned) > 4000:
            pruned = dict(sorted(pruned.items(), key=lambda kv: -(int(kv[1].get("last_ok_at") or 0)))[:4000])
        save_json(history_path, pruned)
        save_json(state_path, {"last_fetch": last_fetch})

        log.info(
            "DONE status=%s kept=%d avg_latency=%sms hash=%s",
            report["status"],
            report["kept_nodes"],
            report["avg_latency_ms"],
            report["proxies_hash"],
        )
        print(json.dumps({k: report[k] for k in ("status", "kept_nodes", "alive_nodes", "checked_nodes", "config_valid", "proxies_hash")}, ensure_ascii=False))
        return 0

    except Exception as exc:  # noqa: BLE001
        log.exception("run failed: %s", exc)
        report["status"] = "failed"
        report["failure_reasons"].append(f"{type(exc).__name__}: {exc}"[:300])
        report["finished_at"] = utc_now()
        report["duration_sec"] = round(time.time() - started, 1)
        write_report_only(out_dir, report)
        return 1


if __name__ == "__main__":
    sys.exit(main())
