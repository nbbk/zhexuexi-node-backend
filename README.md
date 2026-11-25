# zhexuexi-node-backend

轻量节点后端 agent：跑在落地机上的静态 Go 二进制。面板是唯一的事实
来源；agent 只做节点拉取（60 秒 ETag），不做面板推送。

当前版 v0.1.9（切片 11：一键安装脚本定稿，装 agent＋Xray-core
v26.11.9＋sing-box 1.14.4 自编译版＋systemd＋入网；agent 监管
Xray 与 sing-box 双核心）。

切片 4 的功能：流量上报与计量（`QueryStats` 读 `user>>>`／
`inbound>>>`、60 秒上报 `POST /api/v1/node/traffic`、本地 spool
断线重放、健康上报随包）＋入站级指派（用户 `inbounds` 字段）
＋修 0.1.3 的删人静默失效 bug（判据改看内存已应用集，热应用
后写盘）。

## 安装

落地机上 root 执行（一键安装，装 agent 与 Xray-core v26.11.9 与
sing-box 1.14.4 自编译版）：

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
（`releases/download/v0.1.9/node-backend-<amd64|arm64>`），下不到则
改走源码编译兜底（`git clone` 仓库，缺 Go 时下载 Go 1.22.2 装到
`/usr/local/go`，`CGO_ENABLED=0 go build`；兜底需要 git，缺了脚本
会明说并停下）。同一次 Release 里还带 sing-box 自编译二进制
（资产名 `sing-box-1.14.4-with-v2ray-api-<amd64|arm64>`，自编译
1.14.4、带 V2Ray API，装到 `/usr/local/bin/sing-box`；已装且版本
是 1.14.4 就跳过，装完校验版本，自检里再验一次）。

前置依赖：脚本在任何下载／安装之前先检查 curl、unzip、tar 与
systemd（须 systemctl 在且 PID 1 是 systemd）。缺 curl／unzip／
tar 时先按检测到的包管理器（按 apt-get／dnf／yum／apk 顺序取第一
个找到的）自动装；装不上、或没检测到包管理器，就停下、不动任何
东西，并一次性列出缺了什么与每样对应的安装命令（按检测到的包管理
器给，能直接复制跑；检测不到包管理器就明说让用户用自家包管理器
装）。缺 systemd 时直接停下并明说需要支持 systemd 的系统，不自动
装、不做非 systemd 保活。脚本内部下载只用 curl，不加 wget 回退。

## 子命令

```bash
node-backend version
# node-backend 0.1.9

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
`If-None-Match` 与 `X-Node-Backend-Version: 0.1.9`）：

- 200 非删除：把 `config_version` / `etag` / `last_pull` 写状态文件，
  再把配置渲染成 Xray 配置并应用（见下）；
- 304：配置没变，但 agent 仍要确保 Xray 在跑（0.1.3 修启动 bug：
  agent／服务器重启后第一次拉取常是 304，旧版直接返回、Xray
  永远不起来）；同时从磁盘 `xray.json` 恢复已应用的用户集。
  若 304 时 Xray 是刚起来的（之前没跑），磁盘配置可能落后于
  热应用过的用户变更，agent 会强制再拉一次全量配置补齐差量，
  删掉的用户重启后也连不上；
- 200 且 `deleted: true`：停 Xray，记一条日志，exit(0) 自停
  （systemd `Restart=on-failure` 不重启正常退出）；
- 拉取出错（连不上、非 2xx/304）：记日志，下个周期再试，不退出；
- 应用出错（渲染失败、Xray 校验不过）：记日志，正在跑的 Xray
  不动，下次配置变化时再试。

日志只走标准输出（systemd journald 接管），不写自己的日志文件。

### Xray 渲染与监管（切片 2）

- 渲染：面板入站 → Xray 配置（`<config-dir>/xray.json`，0600）。
  VLESS＋REALITY（＋Vision）、VLESS＋REALITY＋XHTTP（服务端）、
  api／stats／policy／dokodemo-door（127.0.0.1:10085）；
  REALITY 入站不写 `minClientVer`（第三方客户端版本不受限，0.1.2）；
  HY2／TUIC／AnyTLS 入站由 sing-box 渲染，不进 Xray 配置；
  TLS 入站没证书时报错（证书是切片 7 的事）。
  渲染前先 `xray run -test` 校验，校验不过不应用。
- 监管：Xray 子进程被 kill 后 5 秒内拉起；连续 3 次 10 秒内退出
  则退避 60 秒并记最近错误。`Start()` 在看护循环活着时是 no-op
  （看护循环自己负责重启，避免双 Xray）；`Stop()` 后的 supervisor
  不再复用。
- 控制接口（只绑回环）：`GET /health`、`POST /reload`（立即拉一次）、
  `POST /restart-core`，默认 `127.0.0.1:18081`。`/reload` 与
  `/restart-core` 在 Xray 没跑时先把它起起来，而不是报错。

### 用户热同步（切片 3，AlterInbound）

- 只变用户（新增／删除／轮换 UUID、用户在入站之间移动）时不重启
  Xray：agent 比较新旧用户集（按 email、逐入站），差量走 Xray
  gRPC API 热应用；热应用成功后把渲染结果写盘（0.1.4），磁盘
  `xray.json` 与运行态一致，写盘失败只记日志、不影响已应用的
  运行态。
- 实现走 Xray 自带的 `xray api adu` / `xray api rmu` 子命令（与
  supervisor 用同一个二进制）：`adu` 一次加一个入站的全部新增
  用户（`{"inbounds": [{tag, port, protocol, settings: {clients,
  decryption}}]}`，0600 临时文件、用后删除），`rmu` 一次删一个
  入站的全部待删 email；不引入 grpc／protobuf 依赖，agent 保持
  纯标准库静态二进制。`adu` 按 `Added N user(s) in total` 校验
  个数；API 不通时子命令非零退出，agent 记日志并回退到重写＋
  重启，保证最终一致。
- 结构判断：比较新旧渲染时忽略用户列表（渲染结果去掉各 VLESS
  入站的 `clients` 再算 SHA）；只有用户变了才走热应用，入站
  结构／端口／REALITY 等变了照旧重写＋重启（用户随新配置一起进）。
- 已应用的用户集存在内存里（以最后一次成功应用的配置为准）；
  agent 重启后从磁盘 `xray.json` 里渲染的用户集恢复。
- 0.1.4 修删人静默失效 bug（2026-11-23 实锤）：0.1.3 的 apply
  在渲染结果与磁盘 `xray.json` 完全相同时直接跳过、不调
  `AlterInbound`，而热添加的用户从不写盘、磁盘一直是旧的，
  删人后渲染变回与磁盘相同就跳过（停用未生效，直到恢复拉取
  时 `adu` 报 duplicate 才暴露）。0.1.4 的判据只看内存里已
  应用的用户集，不看磁盘文件；渲染与磁盘相同时、内存集有差
  也照样调 `AlterInbound` 并打 `hot-applied` 日志。
- 每个 VLESS 入站都应用：REALITY 入站的用户带该入站的 flow
  （`xtls-rprx-vision`），XHTTP 入站的用户不带 flow。

### 流量上报与健康（切片 4）

- 每 60 秒随拉配置周期上报一次 `POST /api/v1/node/traffic`
  （mTLS，复用拉配置的客户端）：读 `xray api statsquery` 的
  `user>>>`（按 email）与 `inbound>>>`（按入站 tag）计数器，
  存上次累计值、本次减上次算增量；计数器归零／重启时只清基
  线、不扣回；`api` 入站不计（只有 agent 自己的 API 调用）。
  请求体字段名与面板端约定死：`node_id`、`window_start`、
  `window_end`、`users[{user_key, up, down, inbound_tag}]`、
  `inbounds[{inbound_tag, up, down}]`、`online[{user_key, ips}]`、
  `health{agent_version, xray_version, xray_running,
  xray_restarts, config_version, last_error, cpu_percent, mem_mb}`。
  `user_key` 是面板的 `kind:id` 形式（配置里的 `user_id`，没有
  时从 email 映射：`u-sub-<id>@node`→`subuser:<id>`，
  `u-merged-<id>@node`→`merged:<id>`）。
- `users` 按（用户、入站）分行：Xray 的 `user>>>` 计数器是按
  用户全局的、不分入站，多入站用户归到面板顺序里第一个被指
  派的入站（实际只走 REALITY 入站：XHTTP 是服务端 fallback，
  不进订阅）；`inbounds` 的数来自 `inbound>>>` 计数器，是准
  确的按入站总量。`online[].ips` 本切片为空数组：Xray stats
  不直接给 IP，不编数据。
- 本地 spool：上报失败（面板 unreachable 或非 2xx）时窗口写进
  spool 文件（默认 `<config-dir>/spool.json`，0600），下次上
  报按窗口顺序重放（面板按窗口去重）；超 24 小时未确认的窗口
  丢弃并记错误；上报成功后清掉已确认窗口，只留未确认的。
- 健康随同一次上报带 `health` 对象：`xray_running` 是监管器里
  Xray 是否在跑，`xray_restarts` 是 agent 启动以来监管器重新
  拉起 Xray 的次数（初次启动不计，agent 重启后从 0 计），
  `last_error` 是最近一次 Xray／应用错误（无则空串），
  `config_version` 是最后成功应用的配置版本，`cpu_percent`／
  `mem_mb` 从 `/proc` 读（读不到发 0，不编数）。Xray 停掉时
  也照常上报（只有健康、无流量行），面板 60 秒内能看到
  `xray_running=false` 与最后一条错。

### 入站级指派（切片 4）

- 节点配置下发时每个用户可带 `inbounds` 字段（该用户被指派的
  入站 tag 列表）；字段缺失或空＝全部入站。渲染时只把指派了
  该入站的用户放进该入站的 `clients`，热增删也按入站差分。
  无 `inbounds` 字段时行为与 0.1.3 完全一致。

### 变量原则：随部署变化的值走配置，不写死

域名、IP、端口、路径从一开始就走变量／配置，换值只改配置：

- 入站的域名／SNI／dest／监听地址来自面板入站配置
  （`domain`、`sni`、`reality_dest`、`listen`，默认监听 `0.0.0.0`）；
- agent 的 `config.json` 可配 `xray_path`（默认 `/usr/local/bin/xray`）、
  `xray_config_path`（默认 `<config-dir>/xray.json`）、
  `control_addr`（默认 `127.0.0.1:18081`）、`api_port`（默认 `10085`）、
  `spool_path`（默认 `<config-dir>/spool.json`，切片 4），
  不填用默认值；0.1.0 写出的旧配置文件缺这些字段时自动补默认值；
- 只有回环绑定（127.0.0.1）是安全不变量，不进配置：
  Xray gRPC API 与控制接口只绑回环，非回环地址拒绝启动。

## 目录布局

```
cmd/node-backend/    agent 源码（只用标准库，无第三方依赖）
  main.go            子命令分发、版本号常量
  join.go            入网换证
  client.go          mTLS 客户端与配置拉取（入站／用户类型）
  run.go             60 秒轮询、状态文件与配置应用
  config.go          配置读写（0600，原子写）与默认值
  xray.go            Xray 配置渲染与校验（REALITY／XHTTP）
  alter.go           用户差量与 AlterInbound（`xray api adu`／`rmu`）
  stats.go           QueryStats 读取与窗口增量计算（`xray api statsquery`）
  traffic.go         流量上报、本地 spool、健康块、/proc 采样
  supervisor.go      Xray 子进程监管（拉起、看护、重启、退避）
  control.go         回环控制接口（/health、/reload、/restart-core）
  main_test.go       测试（httptest 桩面板，含 mTLS 端到端）
  xray_test.go       测试（渲染、校验、配置默认值）
  alter_test.go      测试（用户差量、热应用、启动修复、304）
  stats_test.go      测试（增量计算、入站级指派、删人回归）
  traffic_test.go    测试（上报体、spool 重放、健康字段）
  supervisor_test.go 测试（kill 后拉起、崩溃退避、停止）
  control_test.go    测试（健康、重载、重启核心、回环校验）
node-backend.service systemd 单元
install-node-backend.sh 一键安装脚本
go.mod               module github.com/nbbk/zhexuexi-node-backend, go 1.22.2
```

## 配置与状态文件

| 文件 | 说明 |
| --- | --- |
| `/etc/node-backend/config.json` | join 写入：`panel_url`、`node_id`、`cert_file`、`key_file`、`insecure`（0600）；切片 2 可配 `xray_path`、`xray_config_path`、`control_addr`、`api_port`（不填用默认值，见上）；切片 4 可配 `spool_path`（默认 `<config-dir>/spool.json`） |
| `/etc/node-backend/xray.json` | agent 渲染出的 Xray 配置（0600，原子写，先 `xray run -test` 校验；热应用成功后也写盘，与运行态一致） |
| `/etc/node-backend/spool.json` | 未确认的流量窗口（0600）；上报成功后清空，超 24 小时未确认的丢弃 |
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
