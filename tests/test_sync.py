import threading
import tempfile
import unittest
from pathlib import Path

from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES


class SyncTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def incident(self, ref, **over):
        data = {"title": f"事故 {ref}", "description": "车间事故经过",
                "severity": "serious", "quantity": 3, "threshold": 5,
                "external_ref": ref}
        data.update(over)
        return {"type": "incident", "data": data}

    def record(self, ref, incident_ref, kind="narrative", detail="事项内容", **over):
        data = {"kind": kind, "detail": detail, "status": "open",
                "external_ref": ref, "incident_ref": incident_ref}
        data.update(over)
        return {"type": "record", "data": data}

    def audit_actions(self):
        return [e["action"] for e in self.repo.list_audit()]

    # 1. 批次正常合并 + 同批次重传沿用第一次结果
    def test_batch_merge_is_idempotent(self):
        batch = {"batch_ref": "B-1", "operations": [
            self.incident("INC-1"),
            self.record("N-1", "INC-1", detail="平板记录的事故经过"),
        ]}
        first = self.service.submit_batch(batch, "inv-a", "investigator")
        self.assertEqual(first["status"], "completed")
        self.assertFalse(first["replayed"])
        by_seq = {e["sequence"]: e for e in first["entries"]}
        self.assertEqual(by_seq[0]["status"], "applied")
        self.assertEqual(by_seq[1]["status"], "applied")

        item = self.repo.get_item_by_ref("INC-1")
        self.assertEqual(item["version"], 1)

        # 原批次重传：沿用第一次结果，不再产生任何写入
        actions_before = self.audit_actions()
        second = self.service.submit_batch(batch, "inv-a", "investigator")
        self.assertTrue(second["replayed"])
        self.assertEqual(self.audit_actions(), actions_before)
        statuses = {e["sequence"]: e["status"] for e in second["entries"]}
        self.assertEqual(statuses, {0: "applied", 1: "applied"})
        self.assertEqual(self.repo.get_item_by_ref("INC-1")["version"], 1)

        # 不同批次里对同一新事项的重复创建：后到者看到当前版本
        dup = {"batch_ref": "B-1-DUP", "operations": [self.record(
            "N-1", "INC-1", detail="另一名调查员重复提交")]}
        result = self.service.submit_batch(dup, "inv-b", "investigator")
        entry = result["entries"][0]
        self.assertEqual(entry["status"], "rejected")
        self.assertEqual(entry["outcome"]["outcome"], "duplicate")
        self.assertEqual(entry["outcome"]["current"]["detail"], "平板记录的事故经过")
        recs = self.repo.list_records(item["id"])
        self.assertEqual(len(recs), 1)

    # 2. 同一事项平板和中心都改过 → 冲突保留双方内容 → 安全经理裁决后一起生效
    def test_two_sided_edit_waits_for_adjudication(self):
        self.service.submit_batch(
            {"batch_ref": "B-2", "operations": [self.incident("INC-2",
                                                               title="原始标题")]},
            "inv-a", "investigator")
        item = self.repo.get_item_by_ref("INC-2")

        # 中心侧（办公室）将事故转入调查并补充事项：事故版本升到2
        self.service.add_record(item["id"],
                                {"kind": "note", "detail": "中心补充",
                                 "external_ref": "CENTRAL"},
                                "mgr", "safety_manager")
        self.service.transition(item["id"], STATES[1], 1, "mgr",
                                TRANSITION_ROLES[STATES[1]][0])
        central = self.service.get_item(item["id"], "viewer")
        self.assertEqual(central["version"], 2)
        self.assertEqual(central["status"], STATES[1])

        # 平板基于版本1修改：两边都改过
        tablet_batch = {"batch_ref": "B-2-OFFLINE", "operations": [
            {"type": "incident", "data": {
                "title": "平板标题", "description": "平板补充的事故经过",
                "severity": "fatal", "quantity": 9, "threshold": 5,
                "external_ref": "INC-2", "base_version": 1}}]}
        out = self.service.submit_batch(tablet_batch, "inv-a", "investigator")
        entry = out["entries"][0]
        self.assertEqual(entry["status"], "conflict")
        conflict_id = entry["outcome"]["conflict_ids"][0]

        # 冲突双方内容都被保留
        conflicts = self.service.list_conflicts("investigator", "pending")
        self.assertEqual(len(conflicts), 1)
        conflict = self.service.get_conflict(conflict_id, "safety_manager")
        self.assertEqual(conflict["tablet_payload"]["title"], "平板标题")
        self.assertEqual(conflict["server_payload"]["title"], "原始标题")

        # 中心内容在裁决前未被覆盖
        self.assertEqual(self.repo.get_item(item["id"])["title"], "原始标题")

        # 调查员无权裁决
        with self.assertRaises(PermissionDenied):
            self.service.resolve_conflict(
                conflict_id, {"decision": "tablet"}, "inv-a", "investigator")

        # 安全经理合并裁决：逐字段选择保留哪一边，事故新版本与审计同一事务生效
        resolved = self.service.resolve_conflict(conflict_id, {
            "decision": "merge",
            "fields": {"title": "裁决标题", "severity": "fatal",
                       "description": "平板补充的事故经过"}},
            "mgr", "safety_manager")
        self.assertEqual(resolved["conflict"]["status"], "resolved")
        final = self.repo.get_item(item["id"])
        self.assertEqual(final["title"], "裁决标题")
        self.assertEqual(final["severity"], "fatal")
        self.assertEqual(final["description"], "平板补充的事故经过")
        self.assertEqual(final["version"], 3)

        actions = self.audit_actions()
        self.assertIn("import_conflict", actions)
        self.assertIn("adjudication", actions)
        self.assertIn("adjudication_merge", actions)
        self.assertTrue(self.repo.verify_audit_chain())

        # 已裁决冲突不可重复处理
        with self.assertRaises(ConflictError):
            self.service.resolve_conflict(
                conflict_id, {"decision": "server"}, "mgr", "safety_manager")

        # 旧版本仍可追溯
        versions = self.service.list_item_versions(item["id"], "viewer")
        titles = {v["version"]: v["snapshot"]["title"] for v in versions}
        self.assertEqual(titles[1], "原始标题")
        self.assertEqual(titles[2], "原始标题")
        self.assertEqual(titles[3], "裁决标题")

    def test_tablet_and_server_adjudication_decisions(self):
        for decision in ("tablet", "server"):
            self.service.submit_batch(
                {"batch_ref": f"B-DEC-{decision}", "operations": [
                    self.incident(f"INC-DEC-{decision}")]},
                "inv", "investigator")
            item = self.repo.get_item_by_ref(f"INC-DEC-{decision}")
            self.service.transition(item["id"], STATES[1], 1, "mgr",
                                    TRANSITION_ROLES[STATES[1]][0])
            self.service.add_record(item["id"], {"kind": "n", "detail": "中心改",
                                                 "external_ref": "C"},
                                    "mgr", "safety_manager")
            out = self.service.submit_batch(
                {"batch_ref": f"B-DEC-{decision}-T", "operations": [
                    {"type": "incident", "data": {
                        "title": f"平板{decision}", "description": "平板经过",
                        "severity": "moderate", "quantity": 1, "threshold": 5,
                        "external_ref": f"INC-DEC-{decision}", "base_version": 1}}]},
                "inv", "investigator")
            cid = out["entries"][0]["outcome"]["conflict_ids"][0]
            before_version = self.repo.get_item(item["id"])["version"]
            self.service.resolve_conflict(
                cid, {"decision": decision}, "mgr", "safety_manager")
            after = self.repo.get_item(item["id"])
            if decision == "tablet":
                self.assertEqual(after["title"], f"平板{decision}")
            else:
                self.assertEqual(after["title"], f"事故 INC-DEC-{decision}")
            self.assertEqual(after["version"], before_version + 1)
        self.assertTrue(self.repo.verify_audit_chain())

    # 3. 已关闭事故/事项不可覆盖；审计事件不可改写
    def test_closed_entities_are_protected(self):
        self.service.submit_batch(
            {"batch_ref": "B-3", "operations": [
                self.incident("INC-3"),
                self.record("R-3", "INC-3", detail="纠正措施")]},
            "inv-a", "investigator")
        item = self.repo.get_item_by_ref("INC-3")

        # 走在线流程关闭事故（先关闭唯一的未关闭事项）
        self.repo.conn.execute("UPDATE records SET status='closed' WHERE item_id=?",
                               (item["id"],))
        current = self.service.get_item(item["id"], "viewer")
        for target in STATES[1:]:
            current = self.service.transition(
                current["id"], target, current["version"], "mgr",
                TRANSITION_ROLES[target][0])
        self.assertEqual(current["status"], "closed")

        # 平板尝试修改已关闭事故：拒绝
        out = self.service.submit_batch(
            {"batch_ref": "B-3-CLOSED", "operations": [
                {"type": "incident", "data": {
                    "title": "篡改关闭事故", "description": "x", "severity": "minor",
                    "quantity": 1, "threshold": 1, "external_ref": "INC-3",
                    "base_version": item["version"]}}]},
            "inv-a", "investigator")
        self.assertEqual(out["entries"][0]["status"], "rejected")
        self.assertEqual(out["entries"][0]["outcome"]["outcome"], "rejected_closed")
        self.assertNotEqual(self.repo.get_item(item["id"])["title"], "篡改关闭事故")

        # 平板尝试改已关闭事项：拒绝
        out2 = self.service.submit_batch(
            {"batch_ref": "B-3-REC-CLOSED", "operations": [
                self.record("R-3", "INC-3", detail="篡改关闭事项",
                            base_version=1)]},
            "inv-a", "investigator")
        self.assertEqual(out2["entries"][0]["status"], "rejected")
        self.assertEqual(out2["entries"][0]["outcome"]["outcome"], "rejected_closed")

        # 审计事件只能追加：关闭后事件数量只增不减，且哈希链完整
        events_before = self.repo.list_audit()
        n_before = len(events_before)
        hashes_before = [e["entry_hash"] for e in events_before]
        self.service.submit_batch(
            {"batch_ref": "B-3-AGAIN", "operations": [
                self.record("R-3", "INC-3", detail="再次尝试", base_version=1)]},
            "inv-a", "investigator")
        events_after = self.repo.list_audit()
        self.assertGreaterEqual(len(events_after), n_before)
        self.assertEqual([e["entry_hash"] for e in events_after[:n_before]],
                         hashes_before)
        self.assertTrue(self.repo.verify_audit_chain())

    # 4. 两名调查员同时提交相同事故：只接收先到的一份
    def test_concurrent_same_incident_first_wins(self):
        results = {}

        def submit(name, batch_ref, title):
            p = {"batch_ref": batch_ref, "operations": [
                self.incident("INC-RACE", title=title)]}
            results[name] = self.service.submit_batch(p, name, "investigator")

        t1 = threading.Thread(target=submit, args=("a", "B-RA", "甲内容"))
        t2 = threading.Thread(target=submit, args=("b", "B-RB", "乙内容"))
        t1.start(); t2.start(); t1.join(); t2.join()

        statuses = {name: r["entries"][0]["status"] for name, r in results.items()}
        self.assertEqual(sorted(statuses.values()), ["applied", "rejected"])
        loser = "b" if statuses["a"] == "applied" else "a"
        loser_entry = results[loser]["entries"][0]
        self.assertEqual(loser_entry["outcome"]["outcome"], "duplicate")
        # 后到者看到当前事故版本
        self.assertIn("current", loser_entry["outcome"])
        self.assertEqual(loser_entry["outcome"]["current"]["version"], 1)

        # 并发安全：唯一约束保证只有一份事故
        self.assertEqual(len(self.repo.list_items()), 1)
        self.assertTrue(self.repo.verify_audit_chain())

    # 5. 导入失败后按原批次重试，从失败事项继续
    def test_failed_batch_resumes_from_failed_entry(self):
        # 事项引用的事故尚未进入系统（在另一批次，之后才合并）→ 失败并停止
        batch = {"batch_ref": "B-5", "operations": [
            self.record("R-EARLY", "INC-LATER", detail="先到的事项"),
        ]}
        first = self.service.submit_batch(batch, "inv-a", "investigator")
        self.assertEqual(first["status"], "failed")
        self.assertEqual(first["summary"]["failed_at"], 0)
        self.assertEqual(first["entries"][0]["status"], "failed")
        self.assertEqual(len(self.repo.list_items()), 0)

        # 失败也必须有审计事件，不留只改状态没有审计的记录
        actions = self.audit_actions()
        self.assertIn("import_failed", actions)
        self.assertTrue(self.repo.verify_audit_chain())

        # 依赖的事故先由另一批次合并进来
        self.service.submit_batch(
            {"batch_ref": "B-5-DEP", "operations": [self.incident("INC-LATER")]},
            "inv-a", "investigator")

        # 原批次重试：从失败事项继续并成功，不产生重复副作用
        second = self.service.submit_batch(batch, "inv-a", "investigator")
        self.assertEqual(second["status"], "completed")
        self.assertEqual(second["entries"][0]["status"], "applied")
        item = self.repo.get_item_by_ref("INC-LATER")
        self.assertEqual(len(self.repo.list_records(item["id"])), 1)
        self.assertEqual(self.audit_actions().count("import_failed"), 1)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_resume_after_crash_does_not_duplicate(self):
        # 模拟事故条目已提交、批次状态尚未更新时崩溃
        calls = {"n": 0}
        original_mark = self.repo.mark_batch_status

        def flaky(batch_id, status, summary):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated crash before status save")
            return original_mark(batch_id, status, summary)

        self.repo.mark_batch_status = flaky
        batch = {"batch_ref": "B-CRASH", "operations": [self.incident("INC-CRASH")]}
        with self.assertRaises(RuntimeError):
            self.service.submit_batch(batch, "inv", "investigator")
        self.repo.mark_batch_status = original_mark

        # 条目已 applied：重试沿用第一次结果，不产生第二份事故
        retry = self.service.submit_batch(batch, "inv", "investigator")
        self.assertEqual(retry["status"], "completed")
        self.assertEqual(len(self.repo.list_items()), 1)
        creates = [a for a in self.audit_actions() if a == "import_create"]
        self.assertEqual(len(creates), 1)

    # 6. 事项级别的两边修改 → 裁决生效，旧版本可追溯
    def test_record_conflict_and_resolution(self):
        self.service.submit_batch(
            {"batch_ref": "B-6", "operations": [
                self.incident("INC-6"),
                self.record("R-6", "INC-6", detail="平板初版")]},
            "inv-a", "investigator")
        item = self.repo.get_item_by_ref("INC-6")
        rec = self.repo.list_records(item["id"])[0]

        # 中心在线修改事项：版本2
        self.service.add_record  # ensure method exists
        self.repo.conn.execute(
            "UPDATE records SET detail='中心改', version=2 WHERE id=?", (rec["id"],))
        self.repo.append_audit("record_edit_central", "事故", item["id"], "mgr",
                               {"record_id": rec["id"]})

        # 平板基于版本1修改 → 冲突
        out = self.service.submit_batch(
            {"batch_ref": "B-6-T", "operations": [
                self.record("R-6", "INC-6", detail="平板改", base_version=1)]},
            "inv-a", "investigator")
        entry = out["entries"][0]
        self.assertEqual(entry["status"], "conflict")
        cid = entry["outcome"]["conflict_ids"][0]
        conflict = self.service.get_conflict(cid, "safety_manager")
        self.assertEqual(conflict["entity_type"], "record")
        self.assertEqual(conflict["tablet_payload"]["detail"], "平板改")
        self.assertEqual(conflict["server_payload"]["detail"], "中心改")

        # 合并裁决：只选 detail，status 保留中心侧
        result = self.service.resolve_conflict(cid, {
            "decision": "merge", "fields": {"detail": "裁决内容"}},
            "mgr", "safety_manager")
        self.assertEqual(result["record"]["detail"], "裁决内容")
        self.assertEqual(result["record"]["version"], 3)
        self.assertTrue(self.repo.verify_audit_chain())

    # 7. 结构性校验与审计链
    def test_validation_and_chain(self):
        with self.assertRaises(ValidationError):
            self.service.submit_batch(
                {"batch_ref": "B-BAD", "operations": []}, "inv", "investigator")
        with self.assertRaises(ValidationError):
            self.service.submit_batch(
                {"batch_ref": "B-BAD2", "operations": [
                    {"type": "incident", "data": {"external_ref": "X"}}]},
                "inv", "investigator")
        with self.assertRaises(PermissionDenied):
            self.service.submit_batch(
                {"batch_ref": "B-BAD3", "operations": [self.incident("X")]},
                "viewer", "viewer")
        self.assertEqual(self.repo.list_audit(), [])

    # 8. 平板随事故携带的现场照片摘要等嵌套事项在同事务内生效
    def test_nested_records_apply_with_incident(self):
        out = self.service.submit_batch(
            {"batch_ref": "B-NEST", "operations": [
                {"type": "incident", "data": {
                    "title": "嵌套事故", "description": "经过", "severity": "minor",
                    "quantity": 0, "threshold": 1, "external_ref": "INC-N",
                    "records": [
                        {"kind": "photo", "detail": "现场照片摘要A",
                         "external_ref": "P-1"},
                        {"kind": "witness", "detail": "证人陈述",
                         "external_ref": "W-1", "status": "closed"}]}}]},
            "inv", "investigator")
        self.assertEqual(out["entries"][0]["status"], "applied")
        item = self.repo.get_item_by_ref("INC-N")
        recs = self.repo.list_records(item["id"])
        self.assertEqual({r["kind"] for r in recs}, {"photo", "witness"})
        # 事故创建 + 版本快照 + 两条事项在一个事务中
        versions = self.service.list_item_versions(item["id"], "viewer")
        self.assertEqual(len(versions), 1)
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
