# zhexuexi-node-backend

轻量节点后端 agent：跑在落地机上的静态 Go 二进制。面板是唯一的事实
来源；agent 只做节点拉取（60 秒 ETag），不做面板推送。

切片 1（v0.1.0）只做 agent 骨架与入网：节点能入网、agent 能拉到空配
置。Xray / sing-box 核心监管是切片 2 的事，本版不含。

## 安装

落地机上 root 执行（一键安装，装 agent，不含核心）：

```bash
curl -fsSL https://raw.githubusercontent.com/nbbk/zhexuexi-node-backend/main/install-node-backend.sh \
  | bash -s -- --panel https://example.com:11111 \
               --token join_11111111111111111111111111111111 \
               --node-id 1
```

也可以先下载脚本再跑，或用环境变量：

```bash
PANEL_URL=https://example.com:11111 \
JOIN_TOKEN=join_11111111111111111111111111111111 \
NODE_ID=1 ./install-node-backend.sh
```

`--insecure`：跳过面板证书校验，仅开发期用。

干跑（只打印要做的事，不改系统）：

```bash
DRY_RUN=1 ./install-node-backend.sh --panel https://example.com:11111 \
  --token join_11111111111111111111111111111111 --node-id 1
```

安装脚本优先从 GitHub Release 下二进制
（`releases/download/v0.1.0/node-backend-<amd64|arm64>`），下不到则
改走源码编译兜底（`git clone` 仓库，缺 Go 时下载 Go 1.22.2 装到
`/usr/local/go`，`CGO_ENABLED=0 go build`）。

> 注意：v0.1.0 的 Release 在推仓后才建，当前下载主路径会 404，
> 这是预期的；此时脚本会自动走源码编译兜底。

## 子命令

```bash
node-backend version
# node-backend 0.1.0

node-backend join --panel https://example.com:11111 \
  --token join_11111111111111111111111111111111 --node-id 1
# [--insecure] [--config-dir DIR]，默认 /etc/node-backend

node-backend run [--config-dir DIR] [--state-dir DIR]
# 默认配置 /etc/node-backend，状态 /var/lib/node-backend
```

### join

向面板 `POST /api/v1/node-backend/join` 换证书：

- 成功：证书写 `<config-dir>/certs/node.crt`、密钥写
  `<config-dir>/certs/node.key`（均为 0600），再写
  `<config-dir>/config.json`（0600）；
- 失败（令牌不对 400、节点不存在 404、连不上）：报错退出，
  不写半截配置。

### run

读配置，立即拉一次配置，之后每 60 秒拉一次
（`GET /api/v1/node/config`，mTLS 出示入网证书，带
`If-None-Match` 与 `X-Node-Backend-Version: 0.1.0`）：

- 200 非删除：把 `config_version` / `etag` / `last_pull` 写状态文件；
- 304：什么都不做；
- 200 且 `deleted: true`：记一条日志，exit(0) 自停
  （systemd `Restart=on-failure` 不重启正常退出）；
- 拉取出错（连不上、非 2xx/304）：记日志，下个周期再试，不退出。

日志只走标准输出（systemd journald 接管），不写自己的日志文件。

## 目录布局

```
cmd/node-backend/    agent 源码（只用标准库，无第三方依赖）
  main.go            子命令分发、版本号常量
  join.go            入网换证
  client.go          mTLS 客户端与配置拉取
  run.go             60 秒轮询与状态文件
  config.go          配置读写（0600，原子写）
  main_test.go       测试（httptest 桩面板，含 mTLS 端到端）
node-backend.service systemd 单元
install-node-backend.sh 一键安装脚本
go.mod               module github.com/nbbk/zhexuexi-node-backend, go 1.22.2
```

## 配置与状态文件

| 文件 | 说明 |
| --- | --- |
| `/etc/node-backend/config.json` | join 写入：`panel_url`、`node_id`、`cert_file`、`key_file`、`insecure`（0600） |
| `/etc/node-backend/certs/node.crt` | 入网换来的客户端证书，ECDSA P-256，CN=`node-<id>`（0600） |
| `/etc/node-backend/certs/node.key` | 客户端证书私钥（0600） |
| `/var/lib/node-backend/state.json` | 上次成功拉取：`{"config_version": 1, "etag": "\"...\"", "last_pull": "RFC3339"}`（0600） |

`--config-dir` / `--state-dir` 可改路径（测试时指到临时目录）。

## 本地开发

```bash
export PATH=$HOME/workspace/toolchains/go/bin:$PATH
go vet ./...
go test ./...
CGO_ENABLED=0 go build -o node-backend ./cmd/node-backend
```

示例里的域名、IP、UUID、令牌均为假的（`example.com`、
`203.0.113.1`、`11111111-2222-3333-4444-555555555555`、
`join_11111111111111111111111111111111`）。
