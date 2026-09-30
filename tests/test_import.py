import tempfile
import unittest
from pathlib import Path

from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.rules import STATES, TRANSITION_ROLES
from src.service import Service


def _content(title="title", desc="desc", severity="serious", quantity=5, threshold=10):
    return {"title": title, "description": desc, "severity": severity,
            "quantity": quantity, "threshold": threshold}


class ImportBatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    # ------------------------------------------------------------------
    # 幂等：同一批次重传沿用第一次结果，不重复应用
    # ------------------------------------------------------------------
    def test_retransmit_same_batch_is_idempotent(self):
        ops = [{"op": "create_item", "ref": "OI-1", "content": _content()}]
        first = self.service.import_batch("B-1", ops, "tablet", "investigator")
        second = self.service.import_batch("B-1", ops, "tablet", "investigator")
        self.assertEqual(first["status"], "completed")
        self.assertEqual(second["status"], "completed")
        self.assertEqual(first["operations"][0]["status"], "applied")
        # 只创建了一个事项
        with self.repo._lock:
            cnt = self.repo.conn.execute(
                "SELECT COUNT(*) AS n FROM items WHERE external_ref='OI-1'"
            ).fetchone()["n"]
        self.assertEqual(cnt, 1)

    def test_retransmit_after_conflict_keeps_first_result(self):
        # 中心先建，平板同 ref 建 -> 冲突
        self.repo.create_item("center", "desc", "serious", 5, 10, "OI-2", "center")
        ops = [{"op": "create_item", "ref": "OI-2", "content": _content("tablet", "desc")}]
        first = self.service.import_batch("B-2", ops, "tablet", "investigator")
        second = self.service.import_batch("B-2", ops, "tablet", "investigator")
        self.assertEqual(first["operations"][0]["status"], "conflict")
        self.assertEqual(second["operations"][0]["status"], "conflict")
        # 仍然只有一个事项，且内容是先到的中心版本
        item = self.service.get_item(
            self.repo.conn.execute("SELECT id FROM items WHERE external_ref='OI-2'").fetchone()["id"],
            "viewer")
        self.assertEqual(item["title"], "center")

    # ------------------------------------------------------------------
    # 双方都改：保留两边内容等待安全经理裁决
    # ------------------------------------------------------------------
    def test_both_modified_held_for_adjudication(self):
        item = self.repo.create_item("v1", "desc", "serious", 5, 10, "OI-3", "center")
        # 中心侧先改一版
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE items SET title=?, version=version+1 WHERE id=?",
                ("v2-center", item["id"]))
            row = self.repo.conn.execute("SELECT * FROM items WHERE id=?", (item["id"],)).fetchone()
            self.repo._snapshot_item(dict(row), "import", "center", "center edit")
        # 平板基于 v1 也改了
        ops = [{"op": "update_item", "ref": "OI-3", "base_version": 1,
                "content": _content("v2-tablet", "desc")}]
        result = self.service.import_batch("B-3", ops, "tablet", "investigator")
        op = result["operations"][0]
        self.assertEqual(op["status"], "conflict")
        self.assertEqual(op["result"]["server_version"], 2)
        # 两边内容都保留
        conflicts = self.service.list_conflicts("safety_manager")
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["client_snapshot"]["content"]["title"], "v2-tablet")
        self.assertEqual(conflicts[0]["server_snapshot"]["content"]["title"], "v2-center")
        self.assertEqual(conflicts[0]["base_version"], 1)

    def test_adjudicate_accept_client_applies_atomically(self):
        item = self.repo.create_item("v1", "desc", "serious", 5, 10, "OI-4", "center")
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE items SET title=?, version=version+1 WHERE id=?",
                ("v2-center", item["id"]))
            row = self.repo.conn.execute("SELECT * FROM items WHERE id=?", (item["id"],)).fetchone()
            self.repo._snapshot_item(dict(row), "import", "center", "center edit")
        ops = [{"op": "update_item", "ref": "OI-4", "base_version": 1,
                "content": _content("v2-tablet", "desc")}]
        self.service.import_batch("B-4", ops, "tablet", "investigator")
        conflict_id = self.service.list_conflicts("safety_manager")[0]["id"]
        adj = self.service.adjudicate(conflict_id, "accept_client", None,
                                      "manager", "safety_manager")
        self.assertEqual(adj["status"], "adjudicated")
        self.assertEqual(adj["decision"], "accept_client")
        # 事故版本、事项、审计一起生效
        updated = self.service.get_item(item["id"], "viewer")
        self.assertEqual(updated["version"], 3)
        self.assertEqual(updated["title"], "v2-tablet")
        # 批次事项状态同步为已裁决
        batch = self.service.get_import_batch("B-4", "viewer")
        self.assertEqual(batch["operations"][0]["status"], "adjudicated")
        # 旧版本仍可追溯
        versions = self.service.item_versions(item["id"], "viewer")
        self.assertEqual([v["version"] for v in versions], [1, 2, 3])
        # 审计链完整
        self.assertTrue(self.repo.verify_audit_chain())

    def test_adjudicate_accept_server_keeps_center_version(self):
        item = self.repo.create_item("v1", "desc", "serious", 5, 10, "OI-5", "center")
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE items SET title=?, version=version+1 WHERE id=?",
                ("v2-center", item["id"]))
            row = self.repo.conn.execute("SELECT * FROM items WHERE id=?", (item["id"],)).fetchone()
            self.repo._snapshot_item(dict(row), "import", "center", "center edit")
        ops = [{"op": "update_item", "ref": "OI-5", "base_version": 1,
                "content": _content("v2-tablet", "desc")}]
        self.service.import_batch("B-5", ops, "tablet", "investigator")
        conflict_id = self.service.list_conflicts("safety_manager")[0]["id"]
        self.service.adjudicate(conflict_id, "accept_server", None,
                                "manager", "safety_manager")
        updated = self.service.get_item(item["id"], "viewer")
        self.assertEqual(updated["version"], 2)
        self.assertEqual(updated["title"], "v2-center")

    def test_adjudicate_merge_uses_provided_content(self):
        item = self.repo.create_item("v1", "desc", "serious", 5, 10, "OI-6", "center")
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE items SET title=?, version=version+1 WHERE id=?",
                ("v2-center", item["id"]))
            row = self.repo.conn.execute("SELECT * FROM items WHERE id=?", (item["id"],)).fetchone()
            self.repo._snapshot_item(dict(row), "import", "center", "center edit")
        ops = [{"op": "update_item", "ref": "OI-6", "base_version": 1,
                "content": _content("v2-tablet", "desc")}]
        self.service.import_batch("B-6", ops, "tablet", "investigator")
        conflict_id = self.service.list_conflicts("safety_manager")[0]["id"]
        merged = _content("merged-title", "merged-desc", "minor", 1, 10)
        self.service.adjudicate(conflict_id, "merge", merged, "manager", "safety_manager")
        updated = self.service.get_item(item["id"], "viewer")
        self.assertEqual(updated["title"], "merged-title")
        self.assertEqual(updated["severity"], "minor")

    def test_cannot_adjudicate_twice(self):
        item = self.repo.create_item("v1", "desc", "serious", 5, 10, "OI-7", "center")
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE items SET title=?, version=version+1 WHERE id=?",
                ("v2-center", item["id"]))
            row = self.repo.conn.execute("SELECT * FROM items WHERE id=?", (item["id"],)).fetchone()
            self.repo._snapshot_item(dict(row), "import", "center", "center edit")
        ops = [{"op": "update_item", "ref": "OI-7", "base_version": 1,
                "content": _content("v2-tablet", "desc")}]
        self.service.import_batch("B-7", ops, "tablet", "investigator")
        conflict_id = self.service.list_conflicts("safety_manager")[0]["id"]
        self.service.adjudicate(conflict_id, "accept_client", None,
                                "manager", "safety_manager")
        with self.assertRaises(ConflictError):
            self.service.adjudicate(conflict_id, "accept_client", None,
                                    "manager", "safety_manager")

    # ------------------------------------------------------------------
    # 已关闭事项不能覆盖
    # ------------------------------------------------------------------
    def test_closed_item_cannot_be_overwritten(self):
        item = self.repo.create_item("closed", "desc", "serious", 5, 10, "OI-8", "center")
        current = item
        for target in STATES[1:]:
            current = self.service.transition(
                current["id"], target, current["version"], "reviewer",
                TRANSITION_ROLES[target][0])
        self.assertEqual(current["status"], "closed")
        ops = [{"op": "update_item", "ref": "OI-8", "base_version": 1,
                "content": _content("hacked", "desc")}]
        result = self.service.import_batch("B-8", ops, "tablet", "investigator")
        op = result["operations"][0]
        self.assertEqual(op["status"], "conflict")
        self.assertIn("已关闭", op["result"]["message"])
        # 内容未被改写
        unchanged = self.service.get_item(item["id"], "viewer")
        self.assertEqual(unchanged["title"], "closed")

    # ------------------------------------------------------------------
    # 两名调查员同时提交相同事项：先到接收，后到看到当前版本
    # ------------------------------------------------------------------
    def test_concurrent_same_item_first_wins_second_sees_version(self):
        ops_a = [{"op": "create_item", "ref": "OI-9", "content": _content("first", "desc")}]
        ops_b = [{"op": "create_item", "ref": "OI-9", "content": _content("second", "desc")}]
        first = self.service.import_batch("B-9a", ops_a, "tabletA", "investigator")
        second = self.service.import_batch("B-9b", ops_b, "tabletB", "investigator")
        self.assertEqual(first["operations"][0]["status"], "applied")
        self.assertEqual(second["operations"][0]["status"], "conflict")
        # 后到者看到当前事故版本
        self.assertEqual(second["operations"][0]["result"]["server_version"], 1)
        self.assertEqual(second["operations"][0]["result"]["server"]["title"], "first")
        # 只接收一份
        with self.repo._lock:
            cnt = self.repo.conn.execute(
                "SELECT COUNT(*) AS n FROM items WHERE external_ref='OI-9'"
            ).fetchone()["n"]
        self.assertEqual(cnt, 1)

    # ------------------------------------------------------------------
    # 导入失败后按原批次重试，从失败事项继续，不重复应用
    # ------------------------------------------------------------------
    def test_retry_resumes_from_failed_op(self):
        # op1 更新尚不存在的事项 -> 失败；op2 添加记录 -> 因停止而 pending
        ops = [
            {"op": "update_item", "ref": "OI-NEW", "base_version": 1,
             "content": _content("new", "desc", "minor", 1, 10)},
            {"op": "add_record", "item_ref": "OI-REC", "ref": "REC-1",
             "content": {"kind": "photo", "detail": "scene", "status": "open"}},
        ]
        first = self.service.import_batch("B-10", ops, "tablet", "investigator")
        self.assertEqual(first["status"], "failed")
        self.assertEqual(first["operations"][0]["status"], "failed")
        self.assertEqual(first["operations"][1]["status"], "pending")
        # 中心补建被引用的事项
        self.repo.create_item("new", "desc", "minor", 1, 10, "OI-NEW", "center")
        self.repo.create_item("rec", "desc", "minor", 1, 10, "OI-REC", "center")
        # 原批次重试：从失败事项继续，已应用的不重做
        retry = self.service.import_batch("B-10", ops, "tablet", "investigator")
        self.assertEqual(retry["status"], "completed")
        self.assertIn(retry["operations"][0]["status"], ("applied", "skipped"))
        self.assertEqual(retry["operations"][1]["status"], "applied")
        # 没有“只改状态却没有审计事件”的记录
        with self.repo._lock:
            rec_id = self.repo.conn.execute(
                "SELECT id FROM items WHERE external_ref='OI-REC'"
            ).fetchone()["id"]
        events = self.service.audit("viewer", rec_id)
        self.assertTrue(any(e["action"] == "record" for e in events))
        self.assertTrue(self.repo.verify_audit_chain())

    def test_failed_op_does_not_rollback_earlier_applied(self):
        # op1 建事项（应用），op2 引用不存在事项（失败）
        ops = [
            {"op": "create_item", "ref": "OI-11", "content": _content("ok", "desc", "minor", 1, 10)},
            {"op": "add_record", "item_ref": "OI-GONE", "ref": "REC-X",
             "content": {"kind": "photo", "detail": "x", "status": "open"}},
        ]
        result = self.service.import_batch("B-11", ops, "tablet", "investigator")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["operations"][0]["status"], "applied")
        self.assertEqual(result["operations"][1]["status"], "failed")
        # op1 的事项与审计事件都保留
        with self.repo._lock:
            row = self.repo.conn.execute(
                "SELECT id FROM items WHERE external_ref='OI-11'"
            ).fetchone()
        self.assertIsNotNone(row)
        events = self.service.audit("viewer", row["id"])
        self.assertTrue(any(e["action"] == "import" for e in events))
        self.assertTrue(self.repo.verify_audit_chain())

    # ------------------------------------------------------------------
    # 权限
    # ------------------------------------------------------------------
    def test_viewer_cannot_import(self):
        ops = [{"op": "create_item", "ref": "OI-12", "content": _content()}]
        with self.assertRaises(PermissionDenied):
            self.service.import_batch("B-12", ops, "viewer", "viewer")

    def test_viewer_cannot_adjudicate(self):
        with self.assertRaises(PermissionDenied):
            self.service.adjudicate(1, "accept_client", None, "viewer", "viewer")

    def test_empty_operations_rejected(self):
        with self.assertRaises(ValidationError):
            self.service.import_batch("B-13", [], "tablet", "investigator")

    # ------------------------------------------------------------------
    # 记录添加：幂等跳过
    # ------------------------------------------------------------------
    def test_duplicate_record_ref_is_skipped(self):
        self.repo.create_item("item", "desc", "minor", 1, 10, "OI-14", "center")
        ops = [{"op": "add_record", "item_ref": "OI-14", "ref": "REC-1",
                "content": {"kind": "photo", "detail": "scene", "status": "open"}}]
        # 不同批次提交相同记录标识：后到的跳过，沿用首次结果
        first = self.service.import_batch("B-14a", ops, "tablet", "investigator")
        second = self.service.import_batch("B-14b", ops, "tablet", "investigator")
        self.assertEqual(first["operations"][0]["status"], "applied")
        self.assertEqual(second["operations"][0]["status"], "skipped")
        # 只有一条记录
        records = self.service.list_records(
            self.repo.conn.execute("SELECT id FROM items WHERE external_ref='OI-14'").fetchone()["id"],
            "viewer")
        self.assertEqual(len(records), 1)


if __name__ == "__main__":
    unittest.main()
