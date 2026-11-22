# 配置同步

自动维护一份 Mihomo 客户端配置，每 4 小时更新一次。

## 使用

导入一次即可，之后自动刷新：

1. 打开本仓库的 `output/clash.yaml`，点 **Raw**，复制地址
2. 客户端 → 配置文件 → 新建 → URL → 粘贴 → 保存 → 启用
3. 之后每 4 小时仓库自动提交新版本，客户端下拉刷新或重进应用即生效

配置里三个策略组：

| 组 | 类型 | 说明 |
|---|---|---|
| 首选 | select | 手动选择，也可显式选 `DIRECT` |
| 自动 | url-test | 300 秒测速一次，自动挑最快的 |
| 备用 | fallback | 首选不可用时按顺序切换 |

两个自动组都不含 `DIRECT`：全部失效时不会静默直连，保留最后一次选择。

## 运行机制

```
sources.yaml ──► 抓取 ──► 解析 ──► 去重 ──► 实测 ──► 排序 ──► 生成 ──► 校验 ──► 有变化才提交
```

- **解析**：YAML / 标准 URI / Base64 三种格式，支持 vless、vmess、trojan、ss、hysteria2、tuic
- **去重**：按连接参数（协议 + 地址 + 端口 + 凭据 + 传输参数）建指纹，不看名字
- **实测**：每个候选单独起一个内核实例，通过它的 SOCKS5 端口真实请求 `generate_204`，拿到 204 才算可用（不是"端口通就算活"）
- **校验**：生成的配置先过 `mihomo -t`，不通过不落盘

任一环节失败都不覆盖旧配置，只在 `output/report.json` 里记原因：

- 所有来源都抓不到
- 可用节点数低于 `min_valid_nodes`
- 配置校验不通过

## 配置

`config/settings.yaml`：

| 项 | 默认 | 含义 |
|---|---|---|
| `connect_timeout` | 8 | 单节点超时（秒） |
| `max_concurrency` | 20 | 并行检测数 |
| `retries` | 1 | 失败重试 |
| `max_latency_ms` | 3000 | 超时即丢弃 |
| `max_candidates` | 300 | 每轮候选上限 |
| `max_keep` | 100 | 最终保留数 |
| `health_check_interval` | 300 | 客户端测速周期（秒） |
| `min_valid_nodes` | 5 | 低于该值整轮作废 |
| `scoring` | 0.6 / 0.4 | 延迟权重 / 历史成功率权重 |

`config/sources.yaml`：每个来源可配 `enabled`、`timeout`、`min_interval_hours`、`type`（`auto` 自动嗅探 / `clash` / `uri` / `base64`）。

## 本地运行

```bash
python -m venv .venv
pip install -r requirements.txt

python -m src.main --dry-run      # 不实测，只验证链路
python -m src.main --limit 20     # 只测 20 个候选
export MIHOMO_BIN=./bin/mihomo    # 需要内核时才要设
python -m src.main
pytest -q
```

退出码：`0` 成功 / `1` 异常 / `3` 触发安全阀（保留旧配置）。

## 目录

```
.github/workflows/   定时任务
config/              来源与参数
scripts/             内核下载（带 digest 校验）
src/                 采集 / 解析 / 去重 / 检测 / 生成
tests/               单元测试
output/              生成结果（配置文件 + 报告）
state/               历史成绩与抓取记录
```

## 已知限制

1. 云端 Runner 在境外机房，检测结果只代表那台机器，不代表你这台设备所在网络
2. 公开免费节点存活率通常只有一成上下，每轮节点集合都会有变动
3. `raw.githubusercontent.com` 在部分网络下不可达
4. 出口地区识别默认关闭，避免额外请求

## 许可

MIT
