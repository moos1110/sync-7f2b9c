"""来源采集：按 config/sources.yaml 抓取，单源失败不影响其他源。"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import httpx
import yaml

log = logging.getLogger(__name__)

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


@dataclass
class SourceSpec:
    name: str
    url: str
    type: str = "auto"
    enabled: bool = True
    timeout: float = 25.0
    min_interval_hours: float = 0.0


@dataclass
class FetchResult:
    source: SourceSpec
    ok: bool
    content: str = ""
    error: str = ""
    elapsed_ms: int = 0
    bytes: int = 0
    skipped: bool = False


@dataclass
class FetchReport:
    results: list[FetchResult] = field(default_factory=list)

    @property
    def ok_count(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def total(self) -> int:
        return len(self.results)

    def summary(self) -> list[dict]:
        return [
            {
                "name": r.source.name,
                "ok": r.ok,
                "skipped": r.skipped,
                "bytes": r.bytes,
                "elapsed_ms": r.elapsed_ms,
                "error": r.error,
            }
            for r in self.results
        ]


def load_sources(path: str) -> list[SourceSpec]:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    default = data.get("settings") or {}
    specs: list[SourceSpec] = []
    for item in data.get("sources") or []:
        if not isinstance(item, dict) or not item.get("url"):
            continue
        specs.append(
            SourceSpec(
                name=str(item.get("name") or item["url"])[:60],
                url=str(item["url"]).strip(),
                type=str(item.get("type") or default.get("default_type") or "auto"),
                enabled=bool(item.get("enabled", True)),
                timeout=float(item.get("timeout") or default.get("default_timeout") or 25),
                min_interval_hours=float(
                    item.get("min_interval_hours", default.get("default_min_interval_hours", 0)) or 0
                ),
            )
        )
    return specs


def fetch_all(specs: list[SourceSpec], last_fetch: dict[str, float] | None = None) -> FetchReport:
    """并发抓取所有启用来源；任何异常都被收敛为该源的失败记录。"""
    report = FetchReport()
    now = time.time()
    todo: list[SourceSpec] = []
    for spec in specs:
        if not spec.enabled:
            log.info("skip disabled source: %s", spec.name)
            continue
        prev = (last_fetch or {}).get(spec.name, 0.0)
        if spec.min_interval_hours > 0 and prev and (now - prev) < spec.min_interval_hours * 3600:
            report.results.append(
                FetchResult(source=spec, ok=False, skipped=True, error="not due yet")
            )
            log.info("skip not-due source: %s", spec.name)
            continue
        todo.append(spec)

    if not todo:
        return report

    with httpx.Client(
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=True,
        headers={"User-Agent": UA, "Accept": "*/*"},
        trust_env=False,
    ) as client:
        for spec in todo:
            started = time.perf_counter()
            try:
                resp = client.get(spec.url, timeout=spec.timeout)
                elapsed = int((time.perf_counter() - started) * 1000)
                if resp.status_code != 200:
                    raise RuntimeError(f"HTTP {resp.status_code}")
                text = resp.text
                if not text.strip():
                    raise RuntimeError("empty body")
                report.results.append(
                    FetchResult(
                        source=spec,
                        ok=True,
                        content=text,
                        elapsed_ms=elapsed,
                        bytes=len(resp.content),
                    )
                )
                log.info("fetched %s: %d bytes in %dms", spec.name, len(resp.content), elapsed)
            except Exception as exc:  # noqa: BLE001 - 单源异常必须被隔离
                elapsed = int((time.perf_counter() - started) * 1000)
                report.results.append(
                    FetchResult(
                        source=spec,
                        ok=False,
                        error=f"{type(exc).__name__}: {exc}"[:200],
                        elapsed_ms=elapsed,
                    )
                )
                log.warning("fetch failed %s: %s", spec.name, exc)
    return report
