# RFN 完整说明

RFN 是 RocoMITMServer Ver2.3 Untergangsgeweiht 的 MITMScript 底层能力语言,用于定义可审计、可回放、可通过 Web/MCP 调用的本地脚本能力。

## 1. RFN 定位

RFN 是 MITMScript 的底层能力语言和 VM 执行目标。它不是普通 Python 插件,也不是只负责构造 payload 的小工具层。

RFN 负责直接承载以下能力:

- packet 触发
- HTTP endpoint
- 定时任务
- cache / buffer
- SQLite 数据库
- 文件读写
- HTTP client
- inject / query
- event / audit
- session 断流重连与 session_rotate 清理

RKS 是未来的高层脚本语言。RKS 应编译到 RFN Function、RFN 指令和 Manifest binding,不绕过 RFN VM 的 capability、审计、限额和 replay 规则。

## 2. 文件类型

### Function 文件

路径: `MITMScript\Function\*.rfn`

Function 文件定义可执行 RFN 函数。函数可以由 Manifest 绑定触发,也可以由 Web Console、MCP 或导入执行入口手动调用。

示例:

```asm
.function Main(v:u32) -> u32
.no_side_effect true
.deterministic true
  int.add r0, arg0, 1
  ret r0
.end
```

### Manifest 文件

路径: `MITMScript\Manifest\*.rfnmanifest`

Manifest 文件定义触发绑定,把 packet、HTTP 或 schedule 入口绑定到 Function。

示例:

```text
bind http demo
  method GET
  path /rfn/demo
  func Function.Main
end
```

Function 是“做什么”,Manifest 是“什么时候做”。只写 Function 不写 Manifest 时,函数不会自动响应包、HTTP 或定时任务,但仍可通过 `/api/rfn/exec`、Web 面板或 MCP 手动执行。

### 导入脚本

路径: `runtime\scripts\imported_rfn\*.rfn`

导入脚本用于现场临时动作和验证,不污染默认 `MITMScript\Function\`。Web 入口支持 validate / run / import / list / delete。

如果源码不包含 `.function`,Web 层会按本次执行参数数量包装成内部 `Function.__main__`。完整 RFN 文件默认执行 `Function.Main`,也可以指定其它入口函数。

## 3. 基本语法

RFN 函数格式:

```asm
.function Name(arg:type, other:type) -> return_type
.no_side_effect true|false
.deterministic true|false
.capability "db.read" namespace="shop"
.max_ops 10000
  instruction dst, arg0, "literal"
  ret dst
.end
```

常用规则:

- 参数在函数体中用 `arg0`, `arg1` 等访问。
- 通用寄存器为 `r0` 到 `r31`。
- 字符串使用双引号。
- 十六进制字节使用 `hex"010203"`。
- `;` 后为注释。
- `Function.Name` 是静态函数引用。
- `.pure` 已废弃,应使用 `.no_side_effect` 和 `.deterministic`。

## 4. 类型系统

常用类型:

| 类型 | 说明 |
|---|---|
| `bool` | 布尔值 |
| `u32/i32/u64/i64` | 整数 |
| `str` | 字符串 |
| `bytes` | 字节串 |
| `obj` | JSON 风格对象 |
| `arr` | 数组 |
| `map` | 映射 |
| `http_req` | HTTP 请求对象 |
| `http_rsp` | HTTP 响应对象 |
| `packet` | packet 事件对象 |
| `event` | event 对象 |
| `any` | 任意值 |
| `fn` | 静态 RFN 函数引用 |

## 5. Capability

有副作用或访问宿主资源的指令必须声明 capability。

示例:

```asm
.capability "db.read" namespace="shop"
.capability "db.write" namespace="shop"
.capability "http.server" path="/rfn/shop"
.capability "inject.query" targets="ZoneShopGetInfoReq,ZoneShopGetInfoRsp"
.capability "file.write" path="cap_demo*"
```

支持的主要 capability:

| capability | 用途 |
|---|---|
| `route.read` | route/opcode 查询 |
| `schema.read` | schema 查询 |
| `schema.encode` | schema 编码 |
| `schema.decode` | schema 解码 |
| `packet.read` | packet 字段读取 |
| `cache.read/cache.write` | cache 读写 |
| `db.read/db.write` | SQLite 读写 |
| `http.server` | 处理 RFN HTTP endpoint |
| `http.client` | 主动 HTTP 请求 |
| `inject.send` | 发送 packet |
| `inject.query` | 发送请求并等待响应 |
| `schedule.write` | 注册/修改定时任务 |
| `event.emit` | 发布脚本事件 |
| `audit.write` | 写审计 |
| `file.read/file.write` | 文件读写 |
| `session.control` | 关闭当前 live MITM 数据流 |

本项目实用性优先。capability 可以使用粗粒度声明,但 host 仍保留最低限度保护,例如拒绝把整盘根目录、用户主目录、Windows、Program Files 作为写入/删除目标。

## 6. 指令组总览

### Core

控制流: `nop`, `mov`, `ret`, `fail`, `call`, `jmp`, `jz`, `jnz`, `jeq`, `jne`, `jlt`, `jle`, `jgt`, `jge`

整数: `int.add`, `int.sub`, `int.mul`, `int.div`, `int.mod`, `int.neg`, `int.and`, `int.or`, `int.xor`, `int.not`, `int.shl`, `int.shr`, `int.sar`, `int.min`, `int.max`, `int.clamp`

比较: `cmp.eq`, `cmp.ne`, `cmp.lt`, `cmp.le`, `cmp.gt`, `cmp.ge`, `cmp.isnil`, `cmp.exists`

转换: `cast.bool`, `cast.i32`, `cast.u32`, `cast.i64`, `cast.u64`, `cast.str`, `cast.bytes`, `cast.buf`

### Buffer / Protobuf / Reader

Buffer: `buf.new`, `buf.from`, `buf.clear`, `buf.len`, `buf.reserve`, `buf.append`, `buf.append_int`, `buf.patch_int`, `buf.slice`, `buf.take`, `buf.hex`

Protobuf: `pb.tag`, `pb.varint_raw`, `pb.varint`, `pb.svarint`, `pb.bool`, `pb.enum`, `pb.fixed`, `pb.float32`, `pb.float64`, `pb.bytes`, `pb.string`, `pb.message`, `pb.packed_begin`, `pb.packed_varint`, `pb.packed_fixed`, `pb.packed_end`

Reader: `rd.new`, `rd.pos`, `rd.len`, `rd.left`, `rd.eof`, `rd.seek`, `rd.skip`, `rd.int`, `rd.bytes`, `rd.varint`, `rd.tag`, `rd.skip_wire`

### Object / Array / Map / Scalar

Object: `obj.get`, `obj.get_all`, `obj.has`, `obj.set`, `obj.del`, `obj.keys`

Array / Map: `arr.new`, `arr.from`, `arr.len`, `arr.get`, `arr.push`, `map.new`, `map.from_pairs`, `map.get`, `map.set`

String / Bytes / Hash: `str.len`, `str.cat`, `str.contains`, `bytes.len`, `bytes.slice`, `bytes.hex`, `hash.md5`, `hash.sha1`, `hash.sha256`

### Route / Schema / Packet

`route.resolve` 可按 opcode、opcode hex、proto 名或 opcode 名解析 route。

`schema.encode` 和 `schema.decode` 用当前 opcode registry 编解码 payload。

`packet.*` 用于读取 packet 的方向、opcode、payload、decoded、session、序号等字段。

### Cache / Buffer

Cache 是带 TTL 的 key-value 内存缓存。

Buffer 是带上限的 ring buffer。

常用指令:

- `cache.get`
- `cache.set`
- `cache.del`
- `cache.has`
- `cache.ttl`
- `cache.incr`
- `cache.clear`
- `buffer.push`
- `buffer.take`
- `buffer.latest`
- `buffer.clear`

### Database

RFN 使用 SQLite 持久化数据。当前表包括 `kv`, `tables`, `blobs`, `jobs`, `events`。

常用指令:

- KV: `db.get`, `db.put`, `db.del`, `db.has`
- 表式索引: `db.upsert`, `db.select_one`, `db.select_all`, `db.delete_where`
- Blob: `db.put_blob`, `db.get_blob`
- 事务: `db.begin`, `db.commit`, `db.rollback`
- 清理: `db.expire`
- 预注册 SQL: `db.exec`

### File

文件能力:

- `file.exists`
- `file.is_file`
- `file.is_dir`
- `file.stat`
- `file.list`
- `file.read_text`
- `file.read_bytes`
- `file.write_text`
- `file.append_text`
- `file.write_bytes`
- `file.mkdir`
- `file.remove`
- `file.copy`
- `file.move`

### HTTP

HTTP server:

- `http.req_method`
- `http.req_path`
- `http.req_query`
- `http.req_header`
- `http.req_json`
- `http.req_bytes`
- `http.resp_json`
- `http.resp_text`
- `http.resp_bytes`

HTTP client:

- `http.get`
- `http.post_json`
- `http.post_bytes`
- `http.status`
- `http.json`
- `http.bytes`

### Inject / Query

`inject.send` 只发送 packet。

`query.*` 会发送请求并等待后续真实 S2C packet 或 replay observed pair。

常用指令:

- `inject.ready`
- `inject.send`
- `inject.send_hex`
- `query.send`
- `query.where`
- `query.singleflight`
- `query.singleflight_where`
- `inject.ok`
- `inject.info`
- `inject.decoded`
- `inject.payload`
- `inject.error`

`query.singleflight` 用于并发去重。同 key 的多个 caller 共享一次 inject 和同一个响应。

### Schedule / Event / Audit

Schedule:

- `schedule.after`
- `schedule.every`
- `schedule.cron`
- `schedule.cancel`
- `schedule.exists`
- `schedule.next`

Event:

- `event.emit`
- `event.name`
- `event.payload`

Audit:

- `audit.write`
- `audit.metric`
- `audit.attach_packet`

### Session

`session.disconnect dst, reason` 会关闭当前 live MITM session 的 client/upstream 数据流,让真实客户端自然重连。该指令需要 `.capability "session.control"`。

默认脚本已提供:

```text
POST /rfn/reconnect
```

该入口用于实机触发 8195 重连并验证 session_rotate。

## 7. Binding

### Packet Binding

```text
bind packet login_rsp
  direction s2c
  target ZoneLoginRsp
  func Function.RememberLogin
end
```

packet binding 收到匹配 opcode/schema 的 packet 后调用指定函数。

### HTTP Binding

```text
bind http shop_get
  method GET
  path /rfn/shop
  func Function.HttpGetShop
end
```

HTTP binding 会把 `/rfn/*` 请求分发给 RFN 函数。

### Schedule Binding

```text
bind schedule cap_demo_tick
  every_ms 60000
  func Function.ScheduleCapDemo
  job_key cap_demo_tick
end
```

schedule binding 会由 Web 进程内的 scheduler tick 定期执行。

## 8. Session Rotate

Web 进程记录最后一个 non-empty session_key。只要后续捕获到不同 non-empty session_key,即使中间发生断线、退出游戏或 TCP stream 重建,也会触发:

- 清理 session-scope cache
- 清理 session-scope buffer
- 取消 pending query
- 写入 `events.op=session.rotate`

验证工具:

```powershell
python tools\verify_rfn_session_rotate.py --baseline
python tools\verify_rfn_session_rotate.py --verify
```

通过标准:

- session_key 变化
- SQLite `events` 出现 `session.rotate`
- session-scope cache/buffer 清空
- verify exit code 为 0

## 9. Web 控制台

主入口:

- `GET /`
- 顶栏 `RFN` 按钮打开主 Vue RFN 面板

独立入口:

- `GET /rfn-console`

主要 API:

| API | 用途 |
|---|---|
| `GET /api/rfn/status` | RFN runtime 状态 |
| `POST /api/rfn/reload` | 重新加载 Function / Manifest |
| `GET /api/rfn/functions` | 函数列表 |
| `GET /api/rfn/bindings` | binding 列表 |
| `GET /api/rfn/jobs` | 定时任务列表 |
| `POST /api/rfn/jobs/{key}/run` | 立即执行 job |
| `POST /api/rfn/jobs/{key}/enable` | 启用或禁用 job |
| `POST /api/rfn/jobs/{key}/cancel` | 删除 job |
| `GET /api/rfn/db/namespaces` | DB 命名空间 |
| `GET /api/rfn/cache` | cache 浏览 |
| `GET /api/rfn/buffer` | buffer 浏览 |
| `GET /api/rfn/db/events` | audit/events 浏览 |
| `POST /api/rfn/exec` | 手动执行已加载 Function |
| `GET /api/rfn/imports` | 导入脚本列表 |
| `POST /api/rfn/imports/validate` | 校验 RFN 源码 |
| `POST /api/rfn/imports/run` | 临时运行 RFN 源码 |
| `POST /api/rfn/imports` | 保存导入脚本 |
| `POST /api/rfn/imports/{name}/run` | 执行已保存脚本 |
| `DELETE /api/rfn/imports/{name}` | 删除已保存脚本 |

## 10. MCP 入口

MCP 服务配置位于设置页 `services.mcp`:

- `enabled`
- `host`
- `port`
- `auth_token`
- `allow_inject`
- `allow_rfn_exec`
- `allow_rfn_import`

MCP HTTP 入口:

- `GET /health`
- `GET /status`
- `GET /tools`
- `POST /call`

当前工具:

- `status`
- `list_opcodes`
- `decode_payload`
- `encode_payload`
- `inject_packet`
- `rfn_status`
- `rfn_exec`
- `rfn_import_run`
- `rfn_jobs`
- `rfn_job_run`
- `rfn_job_enable`

MCP 注入和 RFN 执行受配置开关控制。

## 11. 示例

### HTTP 返回 JSON

```asm
.function Main(req:http_req) -> http_rsp
.no_side_effect false
.deterministic false
.capability "http.server" path="/rfn/demo"
  map.from_pairs r0, "ok", true, "source", "rfn"
  http.resp_json r1, 200, r0
  ret r1
.end
```

### 写入 DB

```asm
.function SaveValue(v:u32) -> bool
.no_side_effect false
.deterministic false
.capability "db.write" namespace="demo"
  db.put "demo", "value", arg0, 60000
  ret true
.end
```

### 裸脚本导入执行

可以在 Web 面板粘贴以下裸脚本并执行:

```asm
int.add r0, arg0, 1
ret r0
```

参数 JSON:

```json
[41]
```

执行时会被包装为内部 `Function.__main__(arg0:any)`。

### DB-first query

默认 `ShopQuery.rfn` 的模式:

1. HTTP 收到 `/rfn/shop?shop_id=...`
2. 先查 SQLite `shop:<id>`
3. 未命中则 `query.singleflight_where`
4. inject `ZoneShopGetInfoReq`
5. 等待 `ZoneShopGetInfoRsp`
6. predicate 校验响应中的 shop_id
7. 成功写 DB 并返回 JSON

## 12. 验证标准

离线测试:

```powershell
python -m pytest -q
python tools\pack_opcode_schemas.py --config-dir config verify
```

RFN 专项:

```powershell
python -m pytest tests\test_rfn_instruction_set.py tests\test_rfn_capabilities.py tests\test_rfn_live_integration.py tests\test_rfn_capability_matrix.py tests\test_rfn_web_api.py tests\test_mcp_service.py -q
```

实机验证:

1. 启动 Web MITM 和 WinDivert。
2. 登录真实 NRC/洛克王国客户端。
3. 确认 `/api/status.connected=true` 且 `ready_for_inject=true`。
4. 确认 `/api/rfn/status.packet_triggered > 0`。
5. 调用 `/rfn/cap-demo`、`/rfn/shop`、`/api/rfn/exec`、导入脚本入口。
6. 检查 `runtime\scripts\rfn_live.sqlite` 的 `kv/tables/blobs/jobs/events`。
7. 用 `/rfn/reconnect` 或重登验证 session_rotate。

不要把离线 pytest 通过称为实机通过。实机通过必须有真实 8195 session、RFN 触发计数、SQLite/audit 证据和必要的 verify exit code。
