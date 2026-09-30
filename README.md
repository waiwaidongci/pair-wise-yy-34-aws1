# 工伤事故调查与纠正措施

记录工伤经过、伤害、现场和证人，维护调查、纠正措施、验证与关闭流程。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本快照、审计链和离线批次合并。
- `src/service.py`：权限检查、用例编排、并发控制、批次断点续传和裁决。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则、失败和离线同步测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8311
```

默认端口为`8311`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `GET /api/items/{id}/versions`：事故历史版本快照（旧版本可追溯）
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/audit`
- `POST /api/imports/batches`：提交离线调查批次（investigator / safety_manager）
- `GET /api/imports/batches?batch_ref=...`：查询批次处理结果
- `GET /api/conflicts?status=pending`：列出待裁决冲突
- `GET /api/conflicts/{id}`
- `POST /api/conflicts/{id}/resolve`：安全经理裁决（safety_manager）

允许角色：reporter, investigator, safety_manager, viewer。严重度越高、伤害指数越大或未关闭措施越多，优先级越高；严重事故必须在4小时内启动调查。

## 离线调查批次合并

调查员在无网车间记录事故经过、事项与现场照片摘要，回办公室后通过`POST /api/imports/batches`合并：

```json
{
  "batch_ref": "TABLET-2026-09-30-01",
  "operations": [
    {"type": "incident", "data": {
      "external_ref": "OI-7781", "base_version": 3,
      "title": "冲压机挤伤", "description": "事故经过…", "severity": "serious",
      "quantity": 2, "threshold": 1,
      "records": [
        {"external_ref": "P-01", "kind": "photo", "detail": "现场照片摘要…"},
        {"external_ref": "W-01", "kind": "witness", "detail": "证人陈述…"}
      ]
    }},
    {"type": "record", "data": {
      "incident_ref": "OI-7781", "external_ref": "C-09",
      "kind": "action", "detail": "纠正事项…", "base_version": 2}}
  ]
}
```

合并规则：

- **批次幂等**：`batch_ref`唯一。已完成批次重传直接沿用第一次结果；`failed`批次按原批次重试，事故先于事项处理，只重新执行失败条目，已应用/冲突/拒绝条目不重复生效。
- **先到先得**：无`base_version`的新建若中心已存在同`external_ref`事故/事项，后到者得到`duplicate`拒绝并回传当前事故版本；并发提交由唯一索引保证只落一份。
- **两边都改**：携带`base_version`但与中心当前版本不一致时，平板内容与中心快照都写入`conflicts`，状态为`pending`，不覆盖任一方，等待安全经理裁决。
- **关闭保护**：已关闭事故和已关闭事项的导入被拒绝（`rejected_closed`），仅追加审计事件，不改写数据。
- **审计不可变**：任何状态翻转（应用、拒绝、冲突、失败、裁决）都与业务写入在同一SQLite事务内产生一条SHA-256哈希链审计事件；不存在“只改状态没有审计事件”的提交。
- **裁决原子生效**：`decision`取`server`/`tablet`/`merge`（merge逐字段选择，事故可附带事项列表）；事故新版本、事项更新、冲突关闭与审计事件在单事务内提交，旧版本保存在`item_versions`中可通过`/api/items/{id}/versions`追溯。
- 条目结果：`applied`（生效）、`rejected`（duplicate/rejected_closed）、`conflict`（待裁决）、`failed`（依赖未满足，可重试）、`pending`（尚未处理）。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
