from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ENTITY, ID_PREFIX, STATES


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
        entry_statuses = ",".join("'" + s + "'" for s in
                                  ("pending", "applied", "conflict", "rejected", "failed"))
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
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS item_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    version INTEGER NOT NULL,
                    snapshot TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, version)
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
                CREATE TABLE IF NOT EXISTS import_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_ref TEXT NOT NULL UNIQUE,
                    investigator TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'processing'
                        CHECK(status IN ('processing','completed','failed')),
                    summary TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS import_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL REFERENCES import_batches(id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    op_type TEXT NOT NULL CHECK(op_type IN ('incident','record')),
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ({entry_statuses})),
                    outcome TEXT,
                    applied_at TEXT,
                    UNIQUE(batch_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS conflicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL CHECK(entity_type IN ('item','record')),
                    entity_id INTEGER,
                    incident_id INTEGER,
                    tablet_payload TEXT NOT NULL,
                    server_payload TEXT NOT NULL,
                    batch_id INTEGER NOT NULL,
                    entry_id INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','resolved')),
                    resolution TEXT,
                    resolved_by TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT
                );
            """)
            self._migrate()

    def _migrate(self) -> None:
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(records)")}
        if "version" not in cols:
            self.conn.execute("ALTER TABLE records ADD COLUMN version INTEGER NOT NULL DEFAULT 1")

    # ------------------------------------------------------------------ #
    # 审计链：任何状态翻转必须与业务写入在同一事务内调用本方法
    # ------------------------------------------------------------------ #
    @staticmethod
    def _insert_audit(conn: sqlite3.Connection, action: str, entity_type: str,
                      entity_id: int, actor: str, detail: dict,
                      now: str) -> Dict[str, Any]:
        row = conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous, now)
        conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
        return event

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            return self._insert_audit(self.conn, action, entity_type, entity_id,
                                      actor, detail, utc_now())

    @staticmethod
    def _insert_item_version(conn: sqlite3.Connection, item: Dict[str, Any],
                             reason: str, actor: str, now: str) -> None:
        conn.execute(
            """INSERT INTO item_versions(item_id, version, snapshot, reason, actor, created_at)
               VALUES(?,?,?,?,?,?)""",
            (item["id"], item["version"],
             json.dumps(item, ensure_ascii=False, sort_keys=True), reason, actor, now),
        )

    # ------------------------------------------------------------------ #
    # 事故（items）
    # ------------------------------------------------------------------ #
    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str, audit: Optional[dict] = None) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
                item = self.get_item_conn(self.conn, item_id)
                self._insert_item_version(self.conn, item, "create", actor, now)
                if audit is not None:
                    self._insert_audit(self.conn, audit["action"], ENTITY, item_id,
                                       actor, audit["detail"], now)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            return self.get_item_conn(self.conn, item_id)

    @staticmethod
    def get_item_conn(conn: sqlite3.Connection, item_id: int) -> Dict[str, Any]:
        row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("事故不存在")
        return dict(row)

    def get_item_by_ref(self, external_ref: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM items WHERE external_ref=?", (external_ref,)
            ).fetchone()
        return dict(row) if row else None

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
                        actor: str, audit: Optional[dict] = None) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            current = self.get_item_conn(self.conn, item_id)
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("事故不存在")
                raise ConflictError("版本冲突，请刷新后重试")
            updated = self.get_item_conn(self.conn, item_id)
            self._insert_item_version(self.conn, updated, f"transition:{target}", actor, now)
            if audit is not None:
                detail = dict(audit["detail"])
                detail.setdefault("from", current["status"])
                detail.setdefault("to", target)
                self._insert_audit(self.conn, audit["action"], ENTITY, item_id,
                                   actor, detail, now)
        return self.get_item(item_id)

    def list_item_versions(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM item_versions WHERE item_id=? ORDER BY version", (item_id,)
            ).fetchall()
        result = []
        for row in rows:
            entry = dict(row)
            entry["snapshot"] = json.loads(entry["snapshot"])
            result.append(entry)
        return result

    # ------------------------------------------------------------------ #
    # 事项（records）
    # ------------------------------------------------------------------ #
    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str,
                   audit: Optional[dict] = None) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, version,
                       external_ref, created_by, created_at) VALUES(?,?,?,?,1,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
                if audit is not None:
                    self._insert_audit(self.conn, audit["action"], ENTITY, item_id,
                                       actor, audit["detail"], now)
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

    def get_record(self, record_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        if row is None:
            raise NotFoundError("事项不存在")
        return dict(row)

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    # ------------------------------------------------------------------ #
    # 离线导入批次
    # ------------------------------------------------------------------ #
    def register_import_batch(self, batch_ref: str, investigator: str,
                              payload: dict, entries: List[tuple]) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO import_batches(batch_ref, investigator, payload,
                       status, created_at, updated_at) VALUES(?,?,?,'processing',?,?)""",
                    (batch_ref, investigator,
                     json.dumps(payload, ensure_ascii=False, sort_keys=True), now, now),
                )
                batch_id = int(cur.lastrowid)
                for sequence, (op_type, entry_payload) in enumerate(entries):
                    self.conn.execute(
                        """INSERT INTO import_entries(batch_id, sequence, op_type, payload)
                           VALUES(?,?,?,?)""",
                        (batch_id, sequence, op_type,
                         json.dumps(entry_payload, ensure_ascii=False, sort_keys=True)),
                    )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("批次已存在") from exc
        return self.get_import_batch(batch_ref)

    def get_import_batch(self, batch_ref_or_id) -> Dict[str, Any]:
        with self._lock:
            if isinstance(batch_ref_or_id, int):
                row = self.conn.execute(
                    "SELECT * FROM import_batches WHERE id=?", (batch_ref_or_id,)
                ).fetchone()
            else:
                row = self.conn.execute(
                    "SELECT * FROM import_batches WHERE batch_ref=?", (batch_ref_or_id,)
                ).fetchone()
        if row is None:
            raise NotFoundError("批次不存在")
        batch = dict(row)
        batch["payload"] = json.loads(batch["payload"])
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM import_entries WHERE batch_id=? ORDER BY sequence",
                (batch["id"],),
            ).fetchall()
        batch["entries"] = []
        for r in rows:
            entry = dict(r)
            entry["payload"] = json.loads(entry["payload"])
            entry["outcome"] = json.loads(entry["outcome"]) if entry["outcome"] else None
            batch["entries"].append(entry)
        return batch

    def mark_batch_status(self, batch_id: int, status: str, summary: dict) -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE import_batches SET status=?, summary=?, updated_at=? WHERE id=?",
                (status, json.dumps(summary, ensure_ascii=False, sort_keys=True), now, batch_id),
            )

    @staticmethod
    def _finish_entry(conn: sqlite3.Connection, entry_id: int, status: str,
                      outcome: dict, now: str) -> None:
        conn.execute(
            """UPDATE import_entries SET status=?, outcome=?, applied_at=? WHERE id=?""",
            (status, json.dumps(outcome, ensure_ascii=False, sort_keys=True), now, entry_id),
        )

    def _fail_entry(self, conn: sqlite3.Connection, entry: dict, message: str,
                    actor: str, now: str) -> Dict[str, Any]:
        """条目失败：状态翻转与审计事件在同一事务内落库，不留无审计的状态。"""
        outcome = {"outcome": "failed", "message": message}
        self._finish_entry(conn, entry["id"], "failed", outcome, now)
        self._insert_audit(conn, "import_failed", "import_entry", entry["id"], actor, {
            "batch_id": entry["batch_id"], "sequence": entry["sequence"],
            "op_type": entry["op_type"], "message": message,
        }, now)
        return outcome

    @staticmethod
    def _server_item_snapshot(conn: sqlite3.Connection, item_id: int) -> dict:
        item = dict(conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone())
        item["records"] = [dict(r) for r in conn.execute(
            "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,))]
        return item

    def _insert_conflict(self, conn: sqlite3.Connection, entity_type: str,
                         entity_id: Optional[int], incident_id: int,
                         tablet_payload: dict, server_payload: dict,
                         entry: dict, actor: str, now: str) -> int:
        cur = conn.execute(
            """INSERT INTO conflicts(entity_type, entity_id, incident_id, tablet_payload,
               server_payload, batch_id, entry_id, created_by, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (entity_type, entity_id, incident_id,
             json.dumps(tablet_payload, ensure_ascii=False, sort_keys=True),
             json.dumps(server_payload, ensure_ascii=False, sort_keys=True),
             entry["batch_id"], entry["id"], actor, now),
        )
        return int(cur.lastrowid)

    # ---- 条目：事故 ---------------------------------------------------- #
    def apply_incident_entry(self, entry: dict, actor: str) -> Dict[str, Any]:
        now = utc_now()
        data = entry["payload"]
        ref = data["external_ref"]
        base = data.get("base_version")
        with self._lock, self.conn:
            conn = self.conn
            row = conn.execute("SELECT * FROM items WHERE external_ref=?", (ref,)).fetchone()

            if row is None:
                if base is not None:
                    return self._fail_entry(conn, entry, "基准版本指向不存在的事故", actor, now)
                cur = conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (data["title"], data["description"], data["severity"],
                     data["quantity"], data["threshold"], STATES[0], 1, ref, actor, now, now),
                )
                item = self.get_item_conn(conn, int(cur.lastrowid))
                self._insert_item_version(conn, item, "import_create", actor, now)
                self._insert_audit(conn, "import_create", ENTITY, item["id"], actor, {
                    "batch_id": entry["batch_id"], "external_ref": ref,
                    "title": item["title"], "severity": item["severity"],
                }, now)
                record_results = self._merge_nested_records(
                    conn, item["id"], data.get("records", []), entry, actor, now)
                status = "conflict" if record_results["conflict_ids"] else "applied"
                outcome = {"outcome": status, "item": item,
                           "records": record_results["results"],
                           "conflict_ids": record_results["conflict_ids"]}
                self._finish_entry(conn, entry["id"], status, outcome, now)
                return outcome

            item = dict(row)
            current = self._server_item_snapshot(conn, item["id"])

            # 已关闭事故不可覆盖：拒绝并记录审计
            if item["status"] == "closed":
                self._insert_audit(conn, "import_rejected_closed", ENTITY, item["id"], actor, {
                    "batch_id": entry["batch_id"], "external_ref": ref,
                    "reason": "事故已关闭",
                }, now)
                outcome = {"outcome": "rejected_closed", "current": current}
                self._finish_entry(conn, entry["id"], "rejected", outcome, now)
                return outcome

            # 无基准版本而事故已存在 = 重复提交，先到者已接收，后到者只看当前版本
            if base is None:
                outcome = {"outcome": "duplicate", "current": current}
                self._finish_entry(conn, entry["id"], "rejected", outcome, now)
                return outcome

            # 平板与中心版本不一致：两边都改过，保留双方内容等待裁决
            if int(base) != item["version"]:
                conflict_id = self._insert_conflict(
                    conn, "item", item["id"], item["id"], data, current, entry, actor, now)
                self._insert_audit(conn, "import_conflict", ENTITY, item["id"], actor, {
                    "batch_id": entry["batch_id"], "conflict_id": conflict_id,
                    "base_version": int(base), "current_version": item["version"],
                }, now)
                outcome = {"outcome": "conflict", "conflict_ids": [conflict_id],
                           "current": current}
                self._finish_entry(conn, entry["id"], "conflict", outcome, now)
                return outcome

            # 版本一致：应用事故更新
            conn.execute(
                """UPDATE items SET title=?, description=?, severity=?, quantity=?,
                   threshold=?, version=version+1, updated_at=? WHERE id=?""",
                (data["title"], data["description"], data["severity"], data["quantity"],
                 data["threshold"], now, item["id"]),
            )
            updated = self.get_item_conn(conn, item["id"])
            self._insert_item_version(conn, updated, "import_update", actor, now)
            self._insert_audit(conn, "import_update", ENTITY, item["id"], actor, {
                "batch_id": entry["batch_id"], "external_ref": ref,
                "from_version": item["version"], "to_version": updated["version"],
            }, now)
            record_results = self._merge_nested_records(
                conn, item["id"], data.get("records", []), entry, actor, now)
            status = "conflict" if record_results["conflict_ids"] else "applied"
            outcome = {"outcome": status, "item": updated,
                       "records": record_results["results"],
                       "conflict_ids": record_results["conflict_ids"]}
            self._finish_entry(conn, entry["id"], status, outcome, now)
            return outcome

    def _merge_nested_records(self, conn: sqlite3.Connection, item_id: int,
                              records: List[dict], entry: dict, actor: str,
                              now: str) -> Dict[str, Any]:
        results: List[dict] = []
        conflict_ids: List[int] = []
        for r in records:
            ref = r["external_ref"]
            row = conn.execute(
                "SELECT * FROM records WHERE item_id=? AND external_ref=?",
                (item_id, ref),
            ).fetchone()
            if row is None:
                cur = conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, version,
                       external_ref, created_by, created_at) VALUES(?,?,?,?,1,?,?,?)""",
                    (item_id, r["kind"], r["detail"], r.get("status", "open"),
                     ref, actor, now),
                )
                rec = dict(conn.execute(
                    "SELECT * FROM records WHERE id=?", (int(cur.lastrowid),)).fetchone())
                self._insert_audit(conn, "record_import", ENTITY, item_id, actor, {
                    "batch_id": entry["batch_id"], "record_id": rec["id"],
                    "external_ref": ref, "kind": rec["kind"],
                }, now)
                results.append({"outcome": "applied", "record": rec})
                continue
            rec = dict(row)
            server = dict(rec)
            base = r.get("base_version")
            if base is None:
                # 平板未携带该事项的基准版本：中心已有先到的一份，只回传当前版本
                results.append({"outcome": "duplicate", "current": server})
                continue
            if rec["status"] == "closed":
                self._insert_audit(conn, "record_rejected_closed", ENTITY, item_id, actor, {
                    "batch_id": entry["batch_id"], "record_id": rec["id"],
                    "external_ref": ref, "reason": "事项已关闭",
                }, now)
                results.append({"outcome": "rejected_closed", "record": server})
                continue
            if base is not None and int(base) != rec["version"]:
                cid = self._insert_conflict(
                    conn, "record", rec["id"], item_id, r, server, entry, actor, now)
                self._insert_audit(conn, "import_conflict", ENTITY, item_id, actor, {
                    "batch_id": entry["batch_id"], "conflict_id": cid,
                    "record_id": rec["id"], "base_version": int(base),
                    "current_version": rec["version"],
                }, now)
                conflict_ids.append(cid)
                results.append({"outcome": "conflict", "conflict_id": cid,
                                "current": server})
                continue
            conn.execute(
                """UPDATE records SET kind=?, detail=?, status=?, version=version+1
                   WHERE id=?""",
                (r["kind"], r["detail"], r.get("status", rec["status"]), rec["id"]),
            )
            new_rec = dict(conn.execute(
                "SELECT * FROM records WHERE id=?", (rec["id"],)).fetchone())
            self._insert_audit(conn, "record_import_update", ENTITY, item_id, actor, {
                "batch_id": entry["batch_id"], "record_id": rec["id"],
                "external_ref": ref, "from_version": rec["version"],
                "to_version": new_rec["version"],
            }, now)
            results.append({"outcome": "applied", "record": new_rec})
        return {"results": results, "conflict_ids": conflict_ids}

    # ---- 条目：独立事项 ----------------------------------------------- #
    def apply_record_entry(self, entry: dict, actor: str) -> Dict[str, Any]:
        now = utc_now()
        data = entry["payload"]
        with self._lock, self.conn:
            conn = self.conn
            item_row = conn.execute(
                "SELECT * FROM items WHERE external_ref=?", (data["incident_ref"],)
            ).fetchone()
            if item_row is None:
                # 依赖的事故尚不存在：本条失败，按原批次重试时从本条继续
                return self._fail_entry(conn, entry, "关联事故不存在，等待重试", actor, now)
            item = dict(item_row)
            row = conn.execute(
                "SELECT * FROM records WHERE item_id=? AND external_ref=?",
                (item["id"], data["external_ref"]),
            ).fetchone()
            base = data.get("base_version")

            if row is None:
                if base is not None:
                    return self._fail_entry(conn, entry, "基准版本指向不存在的事项", actor, now)
                cur = conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, version,
                       external_ref, created_by, created_at) VALUES(?,?,?,?,1,?,?,?)""",
                    (item["id"], data["kind"], data["detail"],
                     data.get("status", "open"), data["external_ref"], actor, now),
                )
                rec = dict(conn.execute(
                    "SELECT * FROM records WHERE id=?", (int(cur.lastrowid),)).fetchone())
                self._insert_audit(conn, "record_import", ENTITY, item["id"], actor, {
                    "batch_id": entry["batch_id"], "record_id": rec["id"],
                    "external_ref": rec["external_ref"], "kind": rec["kind"],
                }, now)
                outcome = {"outcome": "applied", "record": rec}
                self._finish_entry(conn, entry["id"], "applied", outcome, now)
                return outcome

            rec = dict(row)
            if rec["status"] == "closed":
                self._insert_audit(conn, "record_rejected_closed", ENTITY, item["id"], actor, {
                    "batch_id": entry["batch_id"], "record_id": rec["id"],
                    "external_ref": rec["external_ref"], "reason": "事项已关闭",
                }, now)
                outcome = {"outcome": "rejected_closed", "current": rec}
                self._finish_entry(conn, entry["id"], "rejected", outcome, now)
                return outcome

            if base is None:
                outcome = {"outcome": "duplicate", "current": rec}
                self._finish_entry(conn, entry["id"], "rejected", outcome, now)
                return outcome

            if int(base) != rec["version"]:
                cid = self._insert_conflict(
                    conn, "record", rec["id"], item["id"], data, rec, entry, actor, now)
                self._insert_audit(conn, "import_conflict", ENTITY, item["id"], actor, {
                    "batch_id": entry["batch_id"], "conflict_id": cid,
                    "record_id": rec["id"], "base_version": int(base),
                    "current_version": rec["version"],
                }, now)
                outcome = {"outcome": "conflict", "conflict_ids": [cid], "current": rec}
                self._finish_entry(conn, entry["id"], "conflict", outcome, now)
                return outcome

            conn.execute(
                """UPDATE records SET kind=?, detail=?, status=?, version=version+1
                   WHERE id=?""",
                (data["kind"], data["detail"], data.get("status", rec["status"]), rec["id"]),
            )
            new_rec = dict(conn.execute(
                "SELECT * FROM records WHERE id=?", (rec["id"],)).fetchone())
            self._insert_audit(conn, "record_import_update", ENTITY, item["id"], actor, {
                "batch_id": entry["batch_id"], "record_id": rec["id"],
                "external_ref": rec["external_ref"], "from_version": rec["version"],
                "to_version": new_rec["version"],
            }, now)
            outcome = {"outcome": "applied", "record": new_rec}
            self._finish_entry(conn, entry["id"], "applied", outcome, now)
            return outcome

    # ------------------------------------------------------------------ #
    # 冲突裁决
    # ------------------------------------------------------------------ #
    def list_conflicts(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM conflicts"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._conflict(r) for r in rows]

    def get_conflict(self, conflict_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM conflicts WHERE id=?", (conflict_id,)).fetchone()
        if row is None:
            raise NotFoundError("冲突不存在")
        return self._conflict(row)

    @staticmethod
    def _conflict(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        item["tablet_payload"] = json.loads(item["tablet_payload"])
        item["server_payload"] = json.loads(item["server_payload"])
        return item

    def resolve_conflict(self, conflict_id: int, decision: str, fields: dict,
                         actor: str) -> Dict[str, Any]:
        """裁决在单事务内生效：事故新版本/事项更新/冲突关闭/审计事件一起提交。"""
        now = utc_now()
        with self._lock, self.conn:
            conn = self.conn
            row = conn.execute(
                "SELECT * FROM conflicts WHERE id=?", (conflict_id,)).fetchone()
            if row is None:
                raise NotFoundError("冲突不存在")
            conflict = dict(row)
            if conflict["status"] != "pending":
                raise ConflictError("冲突已裁决")
            cur = conn.execute(
                "UPDATE conflicts SET status='resolved', resolution=?, resolved_by=?, "
                "resolved_at=? WHERE id=? AND status='pending'",
                (decision, actor, now, conflict_id),
            )
            if cur.rowcount == 0:
                raise ConflictError("冲突已被其他裁决处理")

            if conflict["entity_type"] == "item":
                result = self._resolve_item_conflict(conn, conflict, decision, fields,
                                                     actor, now)
            else:
                result = self._resolve_record_conflict(conn, conflict, decision, fields,
                                                       actor, now)
            self._insert_audit(conn, "adjudication", "conflict", conflict_id, actor, {
                "decision": decision, "entity_type": conflict["entity_type"],
                "entity_id": conflict["entity_id"], "incident_id": conflict["incident_id"],
                "fields": sorted(fields.keys()),
            }, now)
            result["conflict"] = self.get_conflict_conn(conn, conflict_id)
            return result

    @staticmethod
    def get_conflict_conn(conn: sqlite3.Connection, conflict_id: int) -> dict:
        row = conn.execute("SELECT * FROM conflicts WHERE id=?", (conflict_id,)).fetchone()
        item = dict(row)
        item["tablet_payload"] = json.loads(item["tablet_payload"])
        item["server_payload"] = json.loads(item["server_payload"])
        return item

    def _resolve_item_conflict(self, conn: sqlite3.Connection, conflict: dict,
                               decision: str, fields: dict, actor: str,
                               now: str) -> dict:
        item = self.get_item_conn(conn, conflict["incident_id"])
        if decision == "server":
            # 中心内容保留；仍产生一个新版本与审计，使裁决可追溯
            conn.execute(
                "UPDATE items SET version=version+1, updated_at=? WHERE id=?",
                (now, item["id"]),
            )
            updated = self.get_item_conn(conn, item["id"])
            self._insert_item_version(conn, updated, "adjudication:server", actor, now)
            self._insert_audit(conn, "adjudication_server", ENTITY, item["id"], actor, {
                "conflict_id": conflict["id"], "version": updated["version"],
            }, now)
            return {"item": updated}

        if item["status"] == "closed":
            raise ConflictError("事故已关闭，无法应用平板或合并内容")

        if decision == "tablet":
            tablet = json.loads(conflict["tablet_payload"])
            values = {k: tablet[k] for k in
                      ("title", "description", "severity", "quantity", "threshold")}
            record_ops = tablet.get("records", [])
        else:  # merge：安全经理逐字段选择
            values = {k: fields[k] for k in
                      ("title", "description", "severity", "quantity", "threshold")
                      if k in fields}
            record_ops = fields.get("records", [])
        if not values and decision == "merge":
            raise ConflictError("合并裁决至少选择一个事故字段")
        conn.execute(
            """UPDATE items SET title=COALESCE(?,title), description=COALESCE(?,description),
               severity=COALESCE(?,severity), quantity=COALESCE(?,quantity),
               threshold=COALESCE(?,threshold), version=version+1, updated_at=?
               WHERE id=?""",
            (values.get("title"), values.get("description"), values.get("severity"),
             values.get("quantity"), values.get("threshold"), now, item["id"]),
        )
        updated = self.get_item_conn(conn, item["id"])
        self._insert_item_version(conn, updated, f"adjudication:{decision}", actor, now)
        self._insert_audit(conn, f"adjudication_{decision}", ENTITY, item["id"], actor, {
            "conflict_id": conflict["id"], "fields": sorted(values.keys()),
            "from_version": item["version"], "to_version": updated["version"],
        }, now)
        record_results = self._adjudicate_records(conn, item["id"], record_ops,
                                                  conflict, actor, now)
        return {"item": updated, "records": record_results}

    def _adjudicate_records(self, conn: sqlite3.Connection, item_id: int,
                            record_ops: List[dict], conflict: dict, actor: str,
                            now: str) -> list:
        """裁决附带的事项：按裁决写入，但已关闭事项仍不可覆盖。"""
        results = []
        for r in record_ops:
            row = conn.execute(
                "SELECT * FROM records WHERE item_id=? AND external_ref=?",
                (item_id, r["external_ref"]),
            ).fetchone()
            if row is None:
                cur = conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, version,
                       external_ref, created_by, created_at) VALUES(?,?,?,?,1,?,?,?)""",
                    (item_id, r["kind"], r["detail"], r.get("status", "open"),
                     r["external_ref"], actor, now),
                )
                rec = dict(conn.execute(
                    "SELECT * FROM records WHERE id=?", (int(cur.lastrowid),)).fetchone())
                self._insert_audit(conn, "adjudication_record_create", ENTITY, item_id,
                                   actor, {"conflict_id": conflict["id"],
                                           "record_id": rec["id"]}, now)
                results.append({"outcome": "applied", "record": rec})
                continue
            rec = dict(row)
            if rec["status"] == "closed":
                results.append({"outcome": "rejected_closed", "record": rec})
                continue
            conn.execute(
                """UPDATE records SET kind=?, detail=?, status=?, version=version+1
                   WHERE id=?""",
                (r["kind"], r["detail"], r.get("status", rec["status"]), rec["id"]),
            )
            new_rec = dict(conn.execute(
                "SELECT * FROM records WHERE id=?", (rec["id"],)).fetchone())
            self._insert_audit(conn, "adjudication_record_update", ENTITY, item_id, actor, {
                "conflict_id": conflict["id"], "record_id": rec["id"],
                "from_version": rec["version"], "to_version": new_rec["version"],
            }, now)
            results.append({"outcome": "applied", "record": new_rec})
        return results

    def _resolve_record_conflict(self, conn: sqlite3.Connection, conflict: dict,
                                 decision: str, fields: dict, actor: str,
                                 now: str) -> dict:
        rec = conn.execute("SELECT * FROM records WHERE id=?",
                           (conflict["entity_id"],)).fetchone()
        if rec is None:
            raise NotFoundError("事项已不存在")
        rec = dict(rec)
        if decision == "server":
            self._insert_audit(conn, "adjudication_server", ENTITY, rec["item_id"], actor, {
                "conflict_id": conflict["id"], "record_id": rec["id"],
            }, now)
            return {"record": rec}
        if rec["status"] == "closed":
            raise ConflictError("事项已关闭，无法应用平板或合并内容")
        if decision == "tablet":
            tablet = json.loads(conflict["tablet_payload"])
            values = {k: tablet[k] for k in ("kind", "detail", "status") if k in tablet}
        else:
            values = {k: fields[k] for k in ("kind", "detail", "status") if k in fields}
            if not values:
                raise ConflictError("合并裁决至少选择一个事项字段")
        conn.execute(
            """UPDATE records SET kind=COALESCE(?,kind), detail=COALESCE(?,detail),
               status=COALESCE(?,status), version=version+1 WHERE id=?""",
            (values.get("kind"), values.get("detail"), values.get("status"), rec["id"]),
        )
        new_rec = dict(conn.execute(
            "SELECT * FROM records WHERE id=?", (rec["id"],)).fetchone())
        self._insert_audit(conn, f"adjudication_{decision}", ENTITY, rec["item_id"], actor, {
            "conflict_id": conflict["id"], "record_id": rec["id"],
            "fields": sorted(values.keys()), "from_version": rec["version"],
            "to_version": new_rec["version"],
        }, now)
        return {"record": new_rec}

    # ------------------------------------------------------------------ #
    # 审计查询
    # ------------------------------------------------------------------ #
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

    def close(self) -> None:
        with self._lock:
            self.conn.close()
