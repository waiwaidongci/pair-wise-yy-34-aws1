from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import (ConflictError, NotFoundError, PermissionDenied,
                     ValidationError, normalize_severity, require_number,
                     require_text)
from .rules import ENTITY, ID_PREFIX, STATES, content_equal, MERGE_FIELDS


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS item_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    version INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL,
                    threshold REAL NOT NULL,
                    status TEXT NOT NULL,
                    snapshot TEXT NOT NULL,
                    change_summary TEXT,
                    reason TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, version)
                );
                CREATE INDEX IF NOT EXISTS ix_item_versions_item
                    ON item_versions(item_id, version);
                CREATE TABLE IF NOT EXISTS import_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'processing'
                        CHECK(status IN ('processing','completed','failed')),
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    result TEXT NOT NULL DEFAULT '{{}}'
                );
                CREATE TABLE IF NOT EXISTS import_batch_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    op TEXT NOT NULL,
                    ref TEXT,
                    base_version INTEGER,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','applied','skipped','conflict','failed','adjudicated')),
                    result TEXT,
                    updated_at TEXT,
                    UNIQUE(batch_id, seq)
                );
                CREATE TABLE IF NOT EXISTS conflicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    batch_id TEXT NOT NULL,
                    batch_seq INTEGER NOT NULL,
                    base_version INTEGER,
                    client_snapshot TEXT NOT NULL,
                    server_snapshot TEXT NOT NULL,
                    base_snapshot TEXT,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','adjudicated')),
                    decision TEXT,
                    decided_by TEXT,
                    decided_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_conflicts_status
                    ON conflicts(status);
            """)

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def _fetch_item_locked(self, item_id: int) -> Dict[str, Any]:
        row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def _snapshot_item(self, item: Dict[str, Any], reason: str, actor: str,
                       change_summary: Optional[str] = None) -> None:
        snapshot = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
        self.conn.execute(
            """INSERT INTO item_versions(item_id, version, title, description, severity,
               quantity, threshold, status, snapshot, change_summary, reason, created_by, created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (item["id"], item["version"], item["title"], item["description"], item["severity"],
             item["quantity"], item["threshold"], item["status"], snapshot, change_summary,
             reason, actor, utc_now()),
        )

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            try:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
            except sqlite3.IntegrityError as exc:
                raise ConflictError("external_ref已存在") from exc
            item = self._fetch_item_locked(item_id)
            self._snapshot_item(item, "create", actor, "事故创建")
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
            item = self._fetch_item_locked(item_id)
            self._snapshot_item(item, "transition", actor, f"状态转换至{target}")
        return self.get_item(item_id)

    def transition_with_audit(self, item_id: int, target: str, expected_version: int,
                              actor: str, audit_detail: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
            item = self._fetch_item_locked(item_id)
            self._snapshot_item(item, "transition", actor, f"状态转换至{target}")
            self._append_audit_locked("transition", ENTITY, item_id, actor, audit_detail)
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def _append_audit_locked(self, action: str, entity_type: str, entity_id: int,
                             actor: str, detail: dict) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        cur = self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
        event["id"] = int(cur.lastrowid)
        return event

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            return self._append_audit_locked(action, entity_type, entity_id, actor, detail)

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    # ------------------------------------------------------------------
    # 离线批次导入
    # ------------------------------------------------------------------
    def import_batch(self, batch_id: str, actor: str,
                     operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM import_batches WHERE batch_id=?", (batch_id,)
            ).fetchone()
            if row is None:
                now = utc_now()
                with self.conn:
                    self.conn.execute(
                        """INSERT INTO import_batches(batch_id, status, created_by, created_at, result)
                           VALUES(?,?,?,?,?)""",
                        (batch_id, "processing", actor, now, "{}"),
                    )
                    for seq, op in enumerate(operations, start=1):
                        if not isinstance(op, dict):
                            raise ValidationError("每个操作必须是对象")
                        self.conn.execute(
                            """INSERT INTO import_batch_items(batch_id, seq, op, ref, base_version,
                               payload, status, updated_at) VALUES(?,?,?,?,?,?,?,?)""",
                            (batch_id, seq, op.get("op"), op.get("ref"), op.get("base_version"),
                             json.dumps(op, ensure_ascii=False, sort_keys=True), "pending", now),
                        )
                return self._process_batch(batch_id, actor)
            batch = dict(row)
            if batch["status"] == "completed":
                return self.get_batch(batch_id)
            return self._process_batch(batch_id, actor)

    def _process_batch(self, batch_id: str, actor: str) -> Dict[str, Any]:
        op_rows = self.conn.execute(
            "SELECT * FROM import_batch_items WHERE batch_id=? ORDER BY seq", (batch_id,)
        ).fetchall()
        all_done = True
        for op_row in op_rows:
            if op_row["status"] in ("applied", "skipped", "adjudicated"):
                continue
            result = self._apply_op(batch_id, op_row, actor)
            with self.conn:
                self.conn.execute(
                    "UPDATE import_batch_items SET status=?, result=?, updated_at=? WHERE id=?",
                    (result["status"],
                     json.dumps(result, ensure_ascii=False, sort_keys=True),
                     utc_now(), op_row["id"]),
                )
            if result["status"] == "failed":
                all_done = False
                break
        batch_status = "completed" if all_done else "failed"
        with self.conn:
            self.conn.execute(
                "UPDATE import_batches SET status=?, completed_at=?, result=? WHERE batch_id=?",
                (batch_status, utc_now(),
                 json.dumps(self._batch_result(batch_id), ensure_ascii=False, sort_keys=True),
                 batch_id),
            )
        return self.get_batch(batch_id)

    def _apply_op(self, batch_id: str, op_row: sqlite3.Row,
                  actor: str) -> Dict[str, Any]:
        op = op_row["op"]
        try:
            payload = json.loads(op_row["payload"])
            if op == "create_item":
                return self._op_create_item(batch_id, op_row, payload, actor)
            if op == "update_item":
                return self._op_update_item(batch_id, op_row, payload, actor)
            if op == "add_record":
                return self._op_add_record(batch_id, op_row, payload, actor)
            return {"status": "failed", "error": f"未知操作: {op}",
                    "error_kind": "validation"}
        except (ValidationError, NotFoundError, PermissionDenied, ConflictError) as exc:
            return {"status": "failed", "error": str(exc), "error_kind": exc.kind}
        except (TypeError, ValueError, KeyError) as exc:
            return {"status": "failed", "error": f"操作格式错误: {exc}",
                    "error_kind": "validation"}

    def _op_create_item(self, batch_id: str, op_row: sqlite3.Row,
                         payload: Dict[str, Any], actor: str) -> Dict[str, Any]:
        ref = require_text(payload.get("ref"), "ref", 100)
        content = payload.get("content")
        if not isinstance(content, dict):
            raise ValidationError("content必须是对象")
        title = require_text(content.get("title"), "title", 200)
        description = require_text(content.get("description"), "description")
        severity = normalize_severity(content.get("severity"))
        quantity = require_number(content.get("quantity", 0), "quantity")
        threshold = require_number(content.get("threshold", 1), "threshold", 0.000001)
        now = utc_now()
        with self.conn:
            existing = self.conn.execute(
                "SELECT * FROM items WHERE external_ref=?", (ref,)
            ).fetchone()
            if existing is not None:
                conflict_id = self._insert_conflict(
                    batch_id, op_row, None, content, self._item(existing), None,
                    actor, now, reason="duplicate",
                )
                return {
                    "status": "conflict", "conflict_id": conflict_id,
                    "server_version": existing["version"], "server": self._item(existing),
                    "message": "相同事项已存在，先到版本已接收，后到内容待裁决",
                }
            cur = self.conn.execute(
                """INSERT INTO items(title, description, severity, quantity, threshold,
                   status, version, external_ref, created_by, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (title, description, severity, quantity, threshold, STATES[0], 1,
                 ref, actor, now, now),
            )
            item_id = int(cur.lastrowid)
            item = self._fetch_item_locked(item_id)
            self._snapshot_item(item, "import", actor, f"离线批次{batch_id}创建")
            self._append_audit_locked("import", ENTITY, item_id, actor, {
                "batch_id": batch_id, "seq": op_row["seq"], "ref": ref, "version": 1,
            })
        return {"status": "applied", "item": self.get_item(item_id)}

    def _op_update_item(self, batch_id: str, op_row: sqlite3.Row,
                        payload: Dict[str, Any], actor: str) -> Dict[str, Any]:
        ref = require_text(payload.get("ref"), "ref", 100)
        base_version = payload.get("base_version")
        if base_version is not None and (not isinstance(base_version, int) or base_version < 1):
            raise ValidationError("base_version必须是正整数")
        content = payload.get("content")
        if not isinstance(content, dict):
            raise ValidationError("content必须是对象")
        title = require_text(content.get("title"), "title", 200)
        description = require_text(content.get("description"), "description")
        severity = normalize_severity(content.get("severity"))
        quantity = require_number(content.get("quantity", 0), "quantity")
        threshold = require_number(content.get("threshold", 1), "threshold", 0.000001)
        normalized = {"title": title, "description": description, "severity": severity,
                      "quantity": quantity, "threshold": threshold}
        now = utc_now()
        with self.conn:
            row = self.conn.execute(
                "SELECT * FROM items WHERE external_ref=?", (ref,)
            ).fetchone()
            if row is None:
                raise NotFoundError("事项不存在，无法更新")
            server = self._item(row)
            if server["status"] == "closed":
                conflict_id = self._insert_conflict(
                    batch_id, op_row, base_version, normalized, server, None,
                    actor, now, reason="closed",
                )
                return {
                    "status": "conflict", "conflict_id": conflict_id,
                    "server_version": server["version"], "server": server,
                    "message": "事项已关闭，不能覆盖",
                }
            base_content = None
            if base_version is not None:
                snap = self.conn.execute(
                    "SELECT * FROM item_versions WHERE item_id=? AND version=?",
                    (server["id"], base_version),
                ).fetchone()
                if snap is not None:
                    base_content = json.loads(snap["snapshot"])
            server_changed = base_content is None or server["version"] != base_version
            client_changed = base_content is None or not content_equal(normalized, base_content)
            if not server_changed:
                if not client_changed:
                    return {"status": "skipped", "item": server, "message": "内容无变化"}
                item = self._apply_item_update(
                    server["id"], normalized, actor, "import",
                    f"离线批次{batch_id}第{op_row['seq']}项更新",
                    "import",
                    {"batch_id": batch_id, "seq": op_row["seq"], "ref": ref,
                     "version": server["version"] + 1},
                )
                return {"status": "applied", "item": self.get_item(item["id"])}
            if not client_changed:
                return {"status": "skipped", "item": server,
                        "message": "中心侧已更新而平板无改动，沿用中心版本"}
            conflict_id = self._insert_conflict(
                batch_id, op_row, base_version, normalized, server, base_content,
                actor, now, reason="both_modified",
            )
            return {
                "status": "conflict", "conflict_id": conflict_id,
                "server_version": server["version"], "server": server,
                "message": "双方均已修改，等待安全经理裁决",
            }

    def _op_add_record(self, batch_id: str, op_row: sqlite3.Row,
                       payload: Dict[str, Any], actor: str) -> Dict[str, Any]:
        item_ref = require_text(payload.get("item_ref"), "item_ref", 100)
        ref = payload.get("ref")
        if ref is not None:
            ref = require_text(ref, "ref", 100)
        content = payload.get("content")
        if not isinstance(content, dict):
            raise ValidationError("content必须是对象")
        kind = require_text(content.get("kind"), "kind", 100)
        detail = require_text(content.get("detail"), "detail")
        status = content.get("status", "open")
        if status not in ("open", "closed"):
            raise ValidationError("status必须是open或closed")
        now = utc_now()
        with self.conn:
            item_row = self.conn.execute(
                "SELECT * FROM items WHERE external_ref=?", (item_ref,)
            ).fetchone()
            if item_row is None:
                raise NotFoundError("事项不存在，无法添加记录")
            item = self._item(item_row)
            if ref is not None:
                existing = self.conn.execute(
                    "SELECT * FROM records WHERE item_id=? AND external_ref=?",
                    (item["id"], ref),
                ).fetchone()
                if existing is not None:
                    return {"status": "skipped", "record": dict(existing),
                            "message": "记录已存在，沿用首次结果"}
            try:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item["id"], kind, detail, status, ref, actor, now),
                )
            except sqlite3.IntegrityError:
                existing = self.conn.execute(
                    "SELECT * FROM records WHERE item_id=? AND external_ref=?",
                    (item["id"], ref),
                ).fetchone()
                return {"status": "skipped",
                        "record": dict(existing) if existing else None,
                        "message": "记录已存在，沿用首次结果"}
            record_id = int(cur.lastrowid)
            record = dict(self.conn.execute(
                "SELECT * FROM records WHERE id=?", (record_id,)
            ).fetchone())
            self._append_audit_locked("record", ENTITY, item["id"], actor, {
                "batch_id": batch_id, "seq": op_row["seq"], "record_id": record_id,
                "kind": kind, "status": status,
            })
        return {"status": "applied", "record": record}

    def _apply_item_update(self, item_id: int, content: Dict[str, Any], actor: str,
                           reason: str, summary: str, audit_action: str,
                           audit_detail: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now()
        self.conn.execute(
            """UPDATE items SET title=?, description=?, severity=?, quantity=?, threshold=?,
               version=version+1, updated_at=? WHERE id=?""",
            (content["title"], content["description"], content["severity"],
             content["quantity"], content["threshold"], now, item_id),
        )
        item = self._fetch_item_locked(item_id)
        self._snapshot_item(item, reason, actor, summary)
        self._append_audit_locked(audit_action, ENTITY, item_id, actor, audit_detail)
        return item

    def _insert_conflict(self, batch_id: str, op_row: sqlite3.Row,
                         base_version: Optional[int], client_content: Optional[Dict[str, Any]],
                         server: Dict[str, Any], base_content: Optional[Dict[str, Any]],
                         actor: str, now: str, reason: str = "both_modified") -> int:
        cur = self.conn.execute(
            """INSERT INTO conflicts(item_id, batch_id, batch_seq, base_version,
               client_snapshot, server_snapshot, base_snapshot, status, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (server["id"], batch_id, op_row["seq"], base_version,
             json.dumps({"content": client_content, "base_version": base_version},
                        ensure_ascii=False, sort_keys=True),
             json.dumps({"content": {f: server.get(f) for f in MERGE_FIELDS},
                          "version": server["version"], "status": server["status"]},
                        ensure_ascii=False, sort_keys=True),
             json.dumps(base_content, ensure_ascii=False, sort_keys=True) if base_content else None,
             "pending", now),
        )
        conflict_id = int(cur.lastrowid)
        self._append_audit_locked("conflict", ENTITY, server["id"], actor, {
            "batch_id": batch_id, "seq": op_row["seq"], "conflict_id": conflict_id,
            "reason": reason, "server_version": server["version"],
        })
        return conflict_id

    def _batch_result(self, batch_id: str) -> Dict[str, Any]:
        batch = self.conn.execute(
            "SELECT * FROM import_batches WHERE batch_id=?", (batch_id,)
        ).fetchone()
        ops = self.conn.execute(
            "SELECT * FROM import_batch_items WHERE batch_id=? ORDER BY seq", (batch_id,)
        ).fetchall()
        op_results = []
        for op in ops:
            entry = {"seq": op["seq"], "op": op["op"], "status": op["status"]}
            if op["result"]:
                entry["result"] = json.loads(op["result"])
            op_results.append(entry)
        return {"batch_id": batch_id, "status": batch["status"], "operations": op_results}

    def get_batch(self, batch_id: str) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM import_batches WHERE batch_id=?", (batch_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("批次不存在")
            batch = dict(row)
            batch["result"] = json.loads(batch["result"])
            ops = self.conn.execute(
                "SELECT * FROM import_batch_items WHERE batch_id=? ORDER BY seq", (batch_id,)
            ).fetchall()
            parsed = []
            for op in ops:
                entry = dict(op)
                if entry.get("result"):
                    entry["result"] = json.loads(entry["result"])
                parsed.append(entry)
            batch["operations"] = parsed
            return batch

    # ------------------------------------------------------------------
    # 冲突裁决与版本追溯
    # ------------------------------------------------------------------
    def list_conflicts(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM conflicts"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            for key in ("client_snapshot", "server_snapshot", "base_snapshot"):
                if item.get(key):
                    item[key] = json.loads(item[key])
            result.append(item)
        return result

    def get_conflict(self, conflict_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM conflicts WHERE id=?", (conflict_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("冲突不存在")
            item = dict(row)
            for key in ("client_snapshot", "server_snapshot", "base_snapshot"):
                if item.get(key):
                    item[key] = json.loads(item[key])
            return item

    def adjudicate_conflict(self, conflict_id: int, decision: str,
                            content: Optional[Dict[str, Any]], actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT * FROM conflicts WHERE id=?", (conflict_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("冲突不存在")
            conflict = dict(row)
            if conflict["status"] != "pending":
                raise ConflictError("冲突已裁决，不能重复裁决")
            item = self._fetch_item_locked(conflict["item_id"])
            if decision == "accept_server":
                result_version = item["version"]
            elif decision in ("accept_client", "merge"):
                if decision == "accept_client":
                    client = json.loads(conflict["client_snapshot"])
                    normalized = client.get("content")
                else:
                    normalized = content
                if not isinstance(normalized, dict):
                    raise ValidationError("裁决内容必须是对象")
                title = require_text(normalized.get("title"), "title", 200)
                description = require_text(normalized.get("description"), "description")
                severity = normalize_severity(normalized.get("severity"))
                quantity = require_number(normalized.get("quantity", 0), "quantity")
                threshold = require_number(normalized.get("threshold", 1), "threshold", 0.000001)
                normalized = {"title": title, "description": description, "severity": severity,
                              "quantity": quantity, "threshold": threshold}
                updated = self._apply_item_update(
                    item["id"], normalized, actor, "adjudication",
                    f"冲突{conflict_id}裁决({decision})", "adjudication",
                    {"conflict_id": conflict_id, "decision": decision,
                     "version": item["version"] + 1},
                )
                result_version = updated["version"]
            else:
                raise ValidationError("decision必须是accept_client、accept_server或merge")
            self.conn.execute(
                """UPDATE conflicts SET status='adjudicated', decision=?, decided_by=?, decided_at=?
                   WHERE id=?""",
                (decision, actor, now, conflict_id),
            )
            op_result = {"status": "adjudicated", "decision": decision,
                         "conflict_id": conflict_id, "version": result_version}
            self.conn.execute(
                """UPDATE import_batch_items SET status=?, result=?, updated_at=?
                   WHERE batch_id=? AND seq=?""",
                ("adjudicated",
                 json.dumps(op_result, ensure_ascii=False, sort_keys=True), now,
                 conflict["batch_id"], conflict["batch_seq"]),
            )
            self._append_audit_locked("adjudication", ENTITY, item["id"], actor, {
                "conflict_id": conflict_id, "decision": decision,
                "version": result_version,
            })
            batch = self.conn.execute(
                "SELECT * FROM import_batches WHERE batch_id=?", (conflict["batch_id"],)
            ).fetchone()
            if batch is not None:
                self.conn.execute(
                    "UPDATE import_batches SET result=? WHERE batch_id=?",
                    (json.dumps(self._batch_result(conflict["batch_id"]),
                               ensure_ascii=False, sort_keys=True),
                     conflict["batch_id"]),
                )
        return self.get_conflict(conflict_id)

    def list_item_versions(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM item_versions WHERE item_id=? ORDER BY version", (item_id,)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["snapshot"] = json.loads(item["snapshot"])
            result.append(item)
        return result

    def close(self) -> None:
        with self._lock:
            self.conn.close()
