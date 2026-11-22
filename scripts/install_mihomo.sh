#!/usr/bin/env bash
# 下载并校验 Mihomo 内核（Linux amd64），校验 release 资产 digest。
set -euo pipefail

ASSET_NAME="mihomo-linux-amd64-compatible"
API="https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
AUTH=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
  AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

echo "::group::resolve mihomo release"
RELEASE_JSON=$(curl -sS -m 30 "${AUTH[@]}" -H "Accept: application/vnd.github+json" "$API")
TAG=$(printf '%s' "$RELEASE_JSON" | python -c "import sys,json;print(json.load(sys.stdin)['tag_name'])")
FILE="${ASSET_NAME}-${TAG}.gz"
URL="https://github.com/MetaCubeX/mihomo/releases/download/${TAG}/${FILE}"
DIGEST=$(printf '%s' "$RELEASE_JSON" | FILE="$FILE" python -c "
import os,sys,json
d=json.load(sys.stdin)
name=os.environ['FILE']
for a in d.get('assets',[]):
    if a.get('name')==name:
        print(a.get('digest') or '')
        break
" || true)
echo "tag=${TAG} file=${FILE} digest=${DIGEST:-<none>}"
echo "::endgroup::"

curl -sSL -m 300 -o /tmp/mihomo.gz "$URL"

if [ -n "${DIGEST:-}" ]; then
  echo "${DIGEST#sha256:}  /tmp/mihomo.gz" | sha256sum -c -
else
  echo "::warning::release digest unavailable, skip integrity check"
fi

mkdir -p bin
gunzip -c /tmp/mihomo.gz > bin/mihomo
chmod +x bin/mihomo
./bin/mihomo -v
