#!/usr/bin/env bash
# Install zhexuexi node-backend agent 0.1.2 on a landing (node) machine.
# Installs the agent + the pinned Xray-core v26.11.9 (slice 2); the
# agent supervises Xray and renders its config from the panel.
#
# Usage:
#   install-node-backend.sh --panel https://example.com:11111 \
#       --token join_<32 hex> --node-id 1 [--insecure]
#   PANEL_URL=... JOIN_TOKEN=... NODE_ID=... install-node-backend.sh
#   DRY_RUN=1 install-node-backend.sh --panel ... --token ... --node-id ...
#       dry run: only prints what would be done, changes nothing.
#
# Steps: detect arch -> download release binary (fallback: build from
# source) -> download Xray-core v26.11.9 -> install binary + systemd
# unit -> daemon-reload + enable -> join the panel -> start the
# service -> self-check.
set -euo pipefail

VERSION="0.1.2"
XRAY_VERSION="26.11.9"
REPO="nbbk/zhexuexi-node-backend"
BIN_NAME="node-backend"
BIN_PATH="/usr/local/bin/node-backend"
XRAY_PATH="/usr/local/bin/xray"
UNIT_PATH="/etc/systemd/system/node-backend.service"
CONFIG_DIR="/etc/node-backend"
STATE_DIR="/var/lib/node-backend"

PANEL_URL="${PANEL_URL:-}"
JOIN_TOKEN="${JOIN_TOKEN:-}"
NODE_ID="${NODE_ID:-}"
INSECURE="${INSECURE:-0}"
DRY_RUN="${DRY_RUN:-0}"

usage() {
  echo "Usage: $0 --panel <url> --token <join_token> --node-id <id> [--insecure]"
  echo "  or set PANEL_URL / JOIN_TOKEN / NODE_ID environment variables."
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --panel)    PANEL_URL="$2"; shift 2 ;;
    --token)    JOIN_TOKEN="$2"; shift 2 ;;
    --node-id)  NODE_ID="$2"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    -h|--help)  usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[ -n "$PANEL_URL" ] && [ -n "$JOIN_TOKEN" ] && [ -n "$NODE_ID" ] || usage

# Architecture: x86_64 -> amd64, aarch64/arm64 -> arm64.
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

RELEASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}/${BIN_NAME}-${GOARCH}"
GO_VERSION="1.22.2"
# Xray-core release asset per arch (pinned v26.11.9, build plan §2).
case "$GOARCH" in
  amd64) XRAY_ASSET="Xray-linux-64.zip" ;;
  arm64) XRAY_ASSET="Xray-linux-arm64-v8a.zip" ;;
esac
XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/${XRAY_ASSET}"

run() {
  # run <description> <command...>: in dry-run mode print, else execute.
  local desc="$1"; shift
  if [ "$DRY_RUN" = "1" ]; then
    echo "[dry-run] $desc: $*"
  else
    echo "==> $desc"
    "$@"
  fi
}

if [ "$DRY_RUN" != "1" ] && [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (or set DRY_RUN=1 for a dry run)" >&2
  exit 1
fi

echo "node-backend ${VERSION} installer"
echo "  panel: ${PANEL_URL}"
echo "  node:  ${NODE_ID}"
echo "  arch:  ${GOARCH}"
[ "$DRY_RUN" = "1" ] && echo "  mode:  DRY RUN (nothing will be changed)"

# 1. Obtain the binary: prefer the GitHub Release, fall back to building
#    from source if the download fails.
TMP_BIN="$(mktemp)"
trap 'rm -f "$TMP_BIN"' EXIT
if [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] download ${RELEASE_URL} -> ${BIN_PATH}"
  echo "[dry-run] (download fails -> fallback: git clone ${REPO}, build with Go ${GO_VERSION})"
else
  echo "==> downloading ${RELEASE_URL}"
  if curl -fsSL -o "$TMP_BIN" "$RELEASE_URL"; then
    chmod 755 "$TMP_BIN"
  else
    echo "release download failed; falling back to building from source"
    echo "(note: v${VERSION} release does not exist yet — the download is expected to 404 until the release is created)"
    SRC_DIR="$(mktemp -d)"
    trap 'rm -f "$TMP_BIN"; rm -rf "$SRC_DIR"' EXIT
    git clone "https://github.com/${REPO}" "$SRC_DIR"
    if ! command -v go >/dev/null 2>&1; then
      echo "Go not found; installing Go ${GO_VERSION} to /usr/local/go"
      curl -fsSL -o /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz"
      tar -C /usr/local -xzf /tmp/go.tar.gz
      rm -f /tmp/go.tar.gz
      export PATH="/usr/local/go/bin:$PATH"
    fi
    (cd "$SRC_DIR" && CGO_ENABLED=0 go build -trimpath -o "$TMP_BIN" ./cmd/node-backend)
    chmod 755 "$TMP_BIN"
  fi
  install -m 755 "$TMP_BIN" "$BIN_PATH"
fi

# 1b. Download Xray-core v${XRAY_VERSION} (pinned, build plan §2).
# Skip when the installed binary already reports this version.
if [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] download Xray-core v${XRAY_VERSION} (${XRAY_ASSET}) -> ${XRAY_PATH}"
else
  if [ -x "$XRAY_PATH" ] && "$XRAY_PATH" version 2>/dev/null | grep -q "Xray ${XRAY_VERSION}"; then
    echo "Xray-core v${XRAY_VERSION} already installed, skipping"
  else
    echo "==> downloading Xray-core v${XRAY_VERSION} (${XRAY_ASSET})"
    TMP_XRAY="$(mktemp -d)"
    curl -fsSL -o "${TMP_XRAY}/xray.zip" "$XRAY_URL"
    (cd "$TMP_XRAY" && unzip -o -q xray.zip xray)
    install -m 755 "${TMP_XRAY}/xray" "$XRAY_PATH"
    rm -rf "$TMP_XRAY"
    echo "Xray-core installed: $("$XRAY_PATH" version | head -1)"
  fi
fi

# 2. Install the systemd unit. Prefer the copy shipped next to this
#    script; otherwise write the embedded copy.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] install systemd unit -> ${UNIT_PATH}"
  echo "[dry-run] mkdir -p ${CONFIG_DIR} ${STATE_DIR}"
  echo "[dry-run] systemctl daemon-reload && systemctl enable node-backend"
elif [ -f "${SCRIPT_DIR}/node-backend.service" ]; then
  install -m 644 "${SCRIPT_DIR}/node-backend.service" "$UNIT_PATH"
else
  cat > "$UNIT_PATH" <<'EOF'
[Unit]
Description=zhexuexi node backend agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/node-backend run
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "$UNIT_PATH"
fi
run "create directories" mkdir -p "$CONFIG_DIR" "$STATE_DIR"
run "systemd daemon-reload" systemctl daemon-reload
run "enable service" systemctl enable node-backend

# 3. Join the panel: exchange the token for a client certificate.
JOIN_ARGS=(join --panel "$PANEL_URL" --token "$JOIN_TOKEN" --node-id "$NODE_ID" --config-dir "$CONFIG_DIR")
[ "$INSECURE" = "1" ] && JOIN_ARGS+=(--insecure)
if [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] join panel: node-backend ${JOIN_ARGS[*]//${JOIN_TOKEN}/<token>}"
else
  echo "==> joining panel (node ${NODE_ID})"
  if ! "$BIN_PATH" "${JOIN_ARGS[@]}"; then
    echo "ERROR: join failed — the agent is installed but NOT joined." >&2
    echo "Check the panel URL, node id and join token, then run:" >&2
    echo "  ${BIN_PATH} join --panel ${PANEL_URL} --token <token> --node-id ${NODE_ID}" >&2
    echo "The service has NOT been started." >&2
    exit 1
  fi
  echo "join succeeded"
fi

# 4. Start the service and self-check.
run "start service" systemctl start node-backend
run "self-check: version" "$BIN_PATH" version
run "self-check: service state" systemctl is-active node-backend

echo "done: node-backend ${VERSION} installed and running"
