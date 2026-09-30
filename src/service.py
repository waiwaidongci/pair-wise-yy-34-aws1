from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from .domain import (ConflictError, ValidationError, ensure_role,
                     normalize_severity, require_number, require_text)
from .repository import Repository
from .rules import (ADJUDICATIONS, AUDIT_ROLES, CONFLICT_VIEW_ROLES, CREATE_ROLES,
                    ENTITY, IMPORT_ROLES, RECORD_ROLES, RESOLVE_ROLES, TITLE,
                    VIEW_ROLES, completion_blockers, escalation_required,
                    priority_score, response_deadline_hours, role_for_transition,
                    validate_transition)

INCIDENT_FIELDS = ("title", "description", "severity", "quantity", "threshold")
RECORD_FIELDS = ("kind", "detail", "status")


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository
        # 同一批次并发提交时只允许一个合并线程
        self._batch_locks: Dict[str, threading.Lock] = {}
        self._batch_locks_guard = threading.Lock()

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    # ------------------------------------------------------------------ #
    # 在线用例（原有）
    # ------------------------------------------------------------------ #
    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(
            title, description, severity, quantity, threshold, external_ref, actor,
            audit={"action": "create", "detail": {
                "title": title, "severity": severity, "quantity": quantity,
                "priority": priority_score(severity, quantity, threshold),
            }})
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = self._validate_record_status(payload.get("status", "open"))
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(
            item_id, kind, detail, status, external_ref, actor,
            audit={"action": "record", "detail": {
                "kind": kind, "status": status, "external_ref": external_ref}})
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or isinstance(expected_version, bool) \
                or expected_version < 1:
            raise ValidationError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(
            item_id, target, expected_version, actor,
            audit={"action": "transition", "detail": {
                "escalation_required": escalation_required(
                    item["severity"], item["quantity"], item["threshold"])}})
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def list_item_versions(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_item_versions(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result

    # ------------------------------------------------------------------ #
    # 离线调查批次导入
    # ------------------------------------------------------------------ #
    @staticmethod
    def _validate_record_status(value: Any) -> str:
        if value not in ("open", "closed"):
            raise ValidationError("status必须是open或closed")
        return value

    def _validate_offline_record(self, payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValidationError("事项必须是对象")
        result: Dict[str, Any] = {
            "external_ref": require_text(payload.get("external_ref"),
                                         "record.external_ref", 100),
            "kind": require_text(payload.get("kind"), "record.kind", 100),
            "detail": require_text(payload.get("detail"), "record.detail"),
        }
        if "status" in payload:
            result["status"] = self._validate_record_status(payload["status"])
        if "base_version" in payload and payload["base_version"] is not None:
            base = payload["base_version"]
            if not isinstance(base, int) or isinstance(base, bool) or base < 1:
                raise ValidationError("record.base_version必须是正整数")
            result["base_version"] = base
        return result

    def _validate_incident_op(self, payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValidationError("事故操作必须是对象")
        ref = require_text(payload.get("external_ref"), "incident.external_ref", 100)
        result: Dict[str, Any] = {"external_ref": ref}
        base = payload.get("base_version")
        if base is not None:
            if not isinstance(base, int) or isinstance(base, bool) or base < 1:
                raise ValidationError("base_version必须是正整数")
            result["base_version"] = base
        for field in INCIDENT_FIELDS:
            if field not in payload or payload[field] is None:
                raise ValidationError(f"incident.{field}不能为空")
        result["title"] = require_text(payload["title"], "incident.title", 200)
        result["description"] = require_text(payload["description"], "incident.description")
        result["severity"] = normalize_severity(payload["severity"])
        result["quantity"] = require_number(payload["quantity"], "incident.quantity")
        result["threshold"] = require_number(payload["threshold"],
                                             "incident.threshold", 0.000001)
        nested = payload.get("records", [])
        if not isinstance(nested, list):
            raise ValidationError("incident.records必须是数组")
        result["records"] = [self._validate_offline_record(r) for r in nested]
        return result

    def _validate_record_op(self, payload: Any) -> Dict[str, Any]:
        result = self._validate_offline_record(payload)
        result["incident_ref"] = require_text(
            payload.get("incident_ref") if isinstance(payload, dict) else None,
            "record.incident_ref", 100)
        return result

    def _batch_lock(self, batch_ref: str) -> threading.Lock:
        with self._batch_locks_guard:
            lock = self._batch_locks.get(batch_ref)
            if lock is None:
                lock = threading.Lock()
                self._batch_locks[batch_ref] = lock
            return lock

    def submit_batch(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, IMPORT_ROLES)
        actor = require_text(actor, "actor", 100)
        batch_ref = require_text(payload.get("batch_ref"), "batch_ref", 100)

        lock = self._batch_lock(batch_ref)
        with lock:
            stored = self._try_get_batch(batch_ref)
            if stored is not None:
                if stored["status"] == "completed":
                    # 已完成批次重传：沿用第一次结果（冲突条目也等待裁决，不重复处理）
                    return self._batch_result(stored, replayed=True)
                # failed：导入失败后按原批次重试，从失败事项继续
                # processing：上次在状态落库前中断，沿用同一批次继续
                return self._process_batch(stored)

            ops = payload.get("operations")
            if not isinstance(ops, list) or not ops:
                raise ValidationError("operations必须是非空数组")

            # 先做整批结构校验：不合格批次不入库，调查员可按原批次内容修正后重试
            entries: List[tuple] = []
            for index, op in enumerate(ops):
                if not isinstance(op, dict) or op.get("type") not in ("incident", "record"):
                    raise ValidationError(f"operations[{index}].type必须是incident或record")
                if op["type"] == "incident":
                    entries.append(("incident", self._validate_incident_op(op.get("data"))))
                else:
                    entries.append(("record", self._validate_record_op(op.get("data"))))

            batch = self.repository.register_import_batch(batch_ref, actor, payload, entries)
            return self._process_batch(batch)

    def _process_batch(self, batch: dict) -> Dict[str, Any]:
        actor = batch["investigator"]
        # 事故先于事项处理，保证事项重试时事故已可见
        ordered = sorted(batch["entries"], key=lambda e: (
            0 if e["op_type"] == "incident" else 1, e["sequence"]))
        results: List[Dict[str, Any]] = []
        failed_at: Optional[int] = None
        for entry in ordered:
            if entry["status"] in ("pending", "failed"):
                # pending：首次处理；failed：导入失败后从该事项继续重试
                if entry["op_type"] == "incident":
                    outcome = self.repository.apply_incident_entry(entry, actor)
                else:
                    outcome = self.repository.apply_record_entry(entry, actor)
                status = self._outcome_status(outcome)
            else:
                # applied/conflict/rejected 为终态，沿用第一次结果
                outcome = entry["outcome"] or {}
                status = entry["status"]
            view = {"sequence": entry["sequence"], "op_type": entry["op_type"],
                    "status": status, "outcome": outcome}
            results.append(view)
            if status == "failed" and failed_at is None:
                failed_at = entry["sequence"]
                # 从失败事项停止：后续条目保持 pending，重试本批次时继续
                break

        results.sort(key=lambda r: r["sequence"])
        counts: Dict[str, int] = {}
        for r in results:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        total = len(batch["entries"])
        summary = {"counts": counts, "pending": total - len(results),
                   "failed_at": failed_at}
        status = "failed" if failed_at is not None else "completed"
        self.repository.mark_batch_status(batch["id"], status, summary)
        return {"batch_ref": batch["batch_ref"], "replayed": False,
                "status": status, "summary": summary, "entries": results}

    @staticmethod
    def _batch_result(batch: dict, replayed: bool) -> dict:
        import json as _json
        summary = _json.loads(batch["summary"]) if batch["summary"] else None
        return {"batch_ref": batch["batch_ref"], "replayed": replayed,
                "status": batch["status"], "summary": summary,
                "entries": [Service._entry_view(e) for e in batch["entries"]]}

    @staticmethod
    def _outcome_status(outcome: dict) -> str:
        name = outcome.get("outcome", "pending")
        return {
            "applied": "applied",
            "duplicate": "rejected",
            "rejected_closed": "rejected",
            "conflict": "conflict",
            "failed": "failed",
        }.get(name, "pending")

    @staticmethod
    def _entry_view(entry: dict) -> dict:
        return {"sequence": entry["sequence"], "op_type": entry["op_type"],
                "status": entry["status"], "outcome": entry["outcome"]}

    def _try_get_batch(self, batch_ref: str) -> Optional[dict]:
        try:
            return self.repository.get_import_batch(batch_ref)
        except Exception:
            return None

    def get_batch(self, batch_ref: str, role: str) -> dict:
        ensure_role(role, IMPORT_ROLES)
        if not batch_ref:
            raise ValidationError("batch_ref不能为空")
        batch = self.repository.get_import_batch(batch_ref)
        return self._batch_result(batch, replayed=False)

    # ------------------------------------------------------------------ #
    # 冲突裁决
    # ------------------------------------------------------------------ #
    def list_conflicts(self, role: str, status: Optional[str] = None) -> list:
        ensure_role(role, CONFLICT_VIEW_ROLES)
        return self.repository.list_conflicts(status)

    def get_conflict(self, conflict_id: int, role: str) -> dict:
        ensure_role(role, CONFLICT_VIEW_ROLES)
        return self.repository.get_conflict(conflict_id)

    def resolve_conflict(self, conflict_id: int, payload: Dict[str, Any],
                         actor: str, role: str) -> dict:
        ensure_role(role, RESOLVE_ROLES)
        actor = require_text(actor, "actor", 100)
        decision = payload.get("decision")
        if decision not in ADJUDICATIONS:
            raise ValidationError(f"decision必须是{('/'.join(ADJUDICATIONS))}之一")
        conflict = self.repository.get_conflict(conflict_id)
        fields = self._validate_resolution_fields(conflict, decision,
                                                  payload.get("fields"))
        return self.repository.resolve_conflict(conflict_id, decision, fields, actor)

    def _validate_resolution_fields(self, conflict: dict, decision: str,
                                    raw: Any) -> dict:
        if decision in ("server", "tablet"):
            return {}
        if not isinstance(raw, dict):
            raise ValidationError("merge裁决必须提交fields对象")
        fields: Dict[str, Any] = {}
        if conflict["entity_type"] == "item":
            for key in INCIDENT_FIELDS:
                if key in raw:
                    if key == "title":
                        fields[key] = require_text(raw[key], f"fields.{key}", 200)
                    elif key == "description":
                        fields[key] = require_text(raw[key], f"fields.{key}")
                    elif key == "severity":
                        fields[key] = normalize_severity(raw[key])
                    elif key == "quantity":
                        fields[key] = require_number(raw[key], f"fields.{key}")
                    else:
                        fields[key] = require_number(raw[key], f"fields.{key}", 0.000001)
            record_ops = raw.get("records")
            if record_ops is not None:
                if not isinstance(record_ops, list):
                    raise ValidationError("fields.records必须是数组")
                fields["records"] = [self._validate_offline_record(r)
                                     for r in record_ops]
        else:
            if "kind" in raw:
                fields["kind"] = require_text(raw["kind"], "fields.kind", 100)
            if "detail" in raw:
                fields["detail"] = require_text(raw["detail"], "fields.detail")
            if "status" in raw:
                fields["status"] = self._validate_record_status(raw["status"])
        return fields
