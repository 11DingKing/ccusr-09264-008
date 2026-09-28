"""证据有效期巡检服务。

一次巡检：
1. 在一个串行写事务（BEGIN IMMEDIATE）内读取各材料【当前版本】中
   设有有效期、且材料/版本均未撤回的证据；
2. 按巡检时刻划分为两类：
   - expired   已过期：valid_until <= now；
   - expiring  即将过期：now < valid_until <= now + window_days；
3. 对每条结果以 ``category:version_id`` 为提醒键去重——同一证据同一
   类别只在第一次出现时生成提醒，重复巡检不再重复提醒；
4. 批次与逐条结果作为快照落库，历史批次长期可查；
5. 支持 Idempotency-Key：同一键重放返回首个批次，不产生新批次/提醒。

跨进程/跨线程重复执行因此是幂等的：唯一提醒键 + 唯一幂等键 +
条件插入共同保证。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..domain.enums import InspectionCategory, Role
from ..domain.errors import NotFoundError, PermissionDeniedError, ValidationError
from ..domain.models import InspectionBatch, InspectionFinding, User
from .base import Service, require_roles

DEFAULT_WINDOW_DAYS = 30


class InspectionService(Service):
    # ------------------------------------------------------------- 执行巡检
    def run_inspection(
        self,
        actor: User | None,
        *,
        window_days: int = DEFAULT_WINDOW_DAYS,
        institution_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(
            actor,
            Role.QUALITY_AUTHORITY,
            Role.AUDITOR,
        )
        window_days = self._validate_window(window_days)
        # 审计员可跨机构只读巡检；机构维度只允许质量权威或本机构管理员视角
        scope_institution = None
        if institution_id is not None:
            if not actor.has_role(Role.QUALITY_AUTHORITY) and (
                actor.institution_id != institution_id
            ):
                raise PermissionDeniedError("只能巡检本机构证据")
            scope_institution = institution_id

        def work() -> dict:
            now = self.clock.now_utc()
            horizon = now + timedelta(days=window_days)
            now_iso = now.isoformat()

            expiring: list[dict] = []
            expired: list[dict] = []
            for cand in self.repo.list_validity_candidates(scope_institution):
                due = _parse_utc(cand.valid_until)
                category = self._classify(due, now, horizon)
                if category is None:
                    continue
                item = {
                    "material_id": cand.material_id,
                    "institution_id": cand.institution_id,
                    "kind": cand.kind,
                    "title": cand.title,
                    "version_id": cand.version_id,
                    "valid_until": cand.valid_until,
                    "days_remaining": _whole_days_between(now, due),
                    "category": category,
                }
                if category == InspectionCategory.EXPIRED.value:
                    expired.append(item)
                else:
                    expiring.append(item)

            findings = expired + expiring
            batch_id = self.ids.new_id("insp")
            reminded_count = 0
            finding_rows: list[InspectionFinding] = []

            for idx, item in enumerate(findings, start=1):
                category = item["category"]
                key = f"{category}:{item['version_id']}"
                is_new = self.repo.insert_reminder_ignore(
                    key, category, item["version_id"], now_iso
                )
                existing = None if is_new else self.repo.get_reminder(key)
                if is_new:
                    reminded_count += 1
                finding_rows.append(
                    InspectionFinding(
                        finding_id=f"{batch_id}-f{idx}",
                        batch_id=batch_id,
                        category=category,
                        material_id=item["material_id"],
                        institution_id=item["institution_id"],
                        kind=item["kind"],
                        title=item["title"],
                        version_id=item["version_id"],
                        valid_until=item["valid_until"],
                        days_remaining=item["days_remaining"],
                        reminder_key=key,
                        reminded=is_new,
                        reminded_at=now_iso if is_new else (existing or {}).get(
                            "first_reminded_at"
                        ),
                        created_at=now_iso,
                    )
                )

            batch = InspectionBatch(
                batch_id=batch_id,
                inspected_at=now_iso,
                window_days=window_days,
                expiring_count=len(expiring),
                expired_count=len(expired),
                reminded_count=reminded_count,
                idempotency_key=idempotency_key,
            )
            self.repo.insert_inspection_batch(batch)
            for row in finding_rows:
                self.repo.insert_inspection_finding(row)
            self.audit(
                actor.user_id,
                "evidence.inspected",
                institution_id=scope_institution,
                detail={
                    "batch_id": batch_id,
                    "window_days": window_days,
                    "expiring": len(expiring),
                    "expired": len(expired),
                    "reminded": reminded_count,
                },
            )
            return self._batch_dict(batch, rows=finding_rows)

        return self.idempotent(idempotency_key, work)

    # ------------------------------------------------------------- 查询
    def _scope_institution(self, actor: User) -> str | None:
        """质量权威/审计可跨机构；其他角色（机构管理员）限定本机构。"""
        if actor.has_role(Role.QUALITY_AUTHORITY) or actor.has_role(Role.AUDITOR):
            return None
        return actor.institution_id or ""

    def get_batch(self, actor: User, batch_id: str) -> dict:
        require_roles(
            actor,
            Role.QUALITY_AUTHORITY,
            Role.AUDITOR,
            Role.INSTITUTION_ADMIN,
        )
        batch = self.repo.get_inspection_batch(batch_id)
        if batch is None:
            raise NotFoundError("巡检批次不存在", details={"batch_id": batch_id})
        rows = self.repo.list_inspection_findings(batch_id)
        scope = self._scope_institution(actor)
        if scope is not None:
            rows = [r for r in rows if r.institution_id == scope]
        return self._batch_dict(batch, rows=rows)

    def list_batches(self, actor: User, *, limit: int = 50) -> dict:
        require_roles(
            actor,
            Role.QUALITY_AUTHORITY,
            Role.AUDITOR,
            Role.INSTITUTION_ADMIN,
        )
        if limit < 1 or limit > 500:
            raise ValidationError("limit 取值范围 1..500")
        batches = self.repo.list_inspection_batches(limit)
        return {"batches": [self._batch_summary_dict(b) for b in batches]}

    def list_findings(
        self, actor: User, batch_id: str, category: str | None = None
    ) -> dict:
        """读取某批次的清单；测试/调用方分别取 expiring 与 expired。"""
        require_roles(
            actor,
            Role.QUALITY_AUTHORITY,
            Role.AUDITOR,
            Role.INSTITUTION_ADMIN,
        )
        if self.repo.get_inspection_batch(batch_id) is None:
            raise NotFoundError("巡检批次不存在", details={"batch_id": batch_id})
        if category is not None and category not in {
            InspectionCategory.EXPIRING.value,
            InspectionCategory.EXPIRED.value,
        }:
            raise ValidationError(
                "类别只能是 expiring/expired", details={"category": category}
            )
        rows = self.repo.list_inspection_findings(batch_id, category)
        scope = self._scope_institution(actor)
        if scope is not None:
            rows = [r for r in rows if r.institution_id == scope]
        return {
            "batch_id": batch_id,
            "category": category,
            "findings": [self._finding_dict(r) for r in rows],
        }

    # ------------------------------------------------------------- 辅助
    @staticmethod
    def _validate_window(window_days: int) -> int:
        if isinstance(window_days, bool) or not isinstance(window_days, int):
            raise ValidationError("窗口天数必须是整数")
        if window_days < 1 or window_days > 3650:
            raise ValidationError("窗口天数取值范围 1..3650")
        return window_days

    @staticmethod
    def _classify(
        due: datetime, now: datetime, horizon: datetime
    ) -> str | None:
        if due <= now:
            return InspectionCategory.EXPIRED.value
        if due <= horizon:
            return InspectionCategory.EXPIRING.value
        return None

    def _batch_dict(
        self,
        batch: InspectionBatch,
        *,
        rows: list[InspectionFinding] | None = None,
        expiring: list[dict] | None = None,
        expired: list[dict] | None = None,
    ) -> dict:
        result = self._batch_summary_dict(batch)
        if rows is not None:
            result["expiring"] = [
                self._finding_dict(r)
                for r in rows
                if r.category == InspectionCategory.EXPIRING.value
            ]
            result["expired"] = [
                self._finding_dict(r)
                for r in rows
                if r.category == InspectionCategory.EXPIRED.value
            ]
        else:
            result["expiring"] = expiring or []
            result["expired"] = expired or []
        return result

    @staticmethod
    def _batch_summary_dict(b: InspectionBatch) -> dict:
        return {
            "batch_id": b.batch_id,
            "inspected_at": b.inspected_at,
            "window_days": b.window_days,
            "expiring_count": b.expiring_count,
            "expired_count": b.expired_count,
            "reminded_count": b.reminded_count,
        }

    @staticmethod
    def _finding_dict(f: InspectionFinding) -> dict:
        return {
            "material_id": f.material_id,
            "institution_id": f.institution_id,
            "kind": f.kind,
            "title": f.title,
            "version_id": f.version_id,
            "valid_until": f.valid_until,
            "days_remaining": f.days_remaining,
            "reminder_key": f.reminder_key,
            "reminded": f.reminded,
            "reminded_at": f.reminded_at,
        }


def _parse_utc(value: str) -> datetime:
    moment = datetime.fromisoformat(value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _whole_days_between(now: datetime, due: datetime) -> int:
    """按日历方向给出剩余整天数（过期为负/0），用于展示与断言。"""
    delta = due - now
    seconds = delta.total_seconds()
    if seconds >= 0:
        return int(seconds // 86400)
    return -int((-seconds) // 86400)
