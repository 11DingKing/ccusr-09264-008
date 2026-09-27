"""证据有效期巡检服务。

两类发现：
- expiring（即将过期）：有效期未过，但落在预警窗口 (now, now+warning_days]；
- expired（已过期）：valid_until <= now。

幂等模型（重复执行 Python 脚本/进程也安全）：
- 每次巡检生成一个【批次】（inspection_batches），历史批次永久保留、可查；
- 提醒按 reminder_key 去重（inspection_findings 唯一键）：
  即将过期键含有效期时刻（expiring:{version}:{valid_until}），同一版本在
  同一有效期内只提醒一次，续期后产生新键；已过期键每段有效期一次
  （expired:{version}:{valid_until}），续期后再次过期可再提醒；
- 批次与提醒的对应关系记入 inspection_hits：同一提醒被后续批次重复巡检到
  只追加命中记录，不再生成提醒；
- 全部写入在一个 BEGIN IMMEDIATE 事务内，唯一约束兜底并发，INSERT OR
  IGNORE 保证多进程同时巡检也不会产生重复提醒。
"""
from __future__ import annotations

from datetime import timedelta

from ..domain.enums import InspectionCategory, Role
from ..domain.errors import NotFoundError, PermissionDeniedError, ValidationError
from ..domain.models import (
    EvidenceExpiry,
    ExpiryCandidate,
    InspectionBatch,
    InspectionFinding,
    User,
)
from .base import Service, require_roles, require_user
from .timeutil import resolve_deadline


class ExpiryInspectionService(Service):
    # ---------------------------------------------------------- 有效期登记
    def set_expiry(
        self,
        actor: User,
        *,
        version_id: str,
        valid_until_local_iso: str,
        valid_until_timezone: str | None = None,
        source: str = "",
        note: str = "",
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(actor, Role.INSTITUTION_ADMIN, Role.QUALITY_AUTHORITY)
        valid_until_iso = self._resolve_valid_until(
            valid_until_local_iso, valid_until_timezone
        )

        def work() -> dict:
            version = self.repo.get_version(version_id)
            if version is None:
                raise NotFoundError("版本不存在", details={"version_id": version_id})
            if (
                not actor.has_role(Role.QUALITY_AUTHORITY)
                and version.institution_id != actor.institution_id
            ):
                raise PermissionDeniedError("只能登记本机构证据的有效期")
            if version.withdrawn:
                raise ValidationError("已撤回版本不再参与有效期巡检")
            previous = self.repo.get_expiry(version_id)
            action = "expiry.renewed" if previous is not None else "expiry.registered"
            expiry = EvidenceExpiry(
                version_id=version_id,
                material_id=version.material_id,
                institution_id=version.institution_id,
                valid_until=valid_until_iso,
                set_by=actor.user_id,
                set_at=self.clock.now_iso(),
                source=source,
                note=note,
            )
            self.repo.upsert_expiry(expiry)
            self.audit(
                actor.user_id, action,
                institution_id=version.institution_id,
                detail={
                    "version_id": version_id,
                    "valid_until": valid_until_iso,
                    "previous_valid_until": previous.valid_until if previous else None,
                },
            )
            result = self._expiry_dict(expiry)
            result["renewed"] = previous is not None
            return result

        return self.idempotent(idempotency_key, work)

    def get_expiry(self, actor: User, version_id: str) -> dict:
        require_user(actor)
        version = self.repo.get_version(version_id)
        if version is None:
            raise NotFoundError("版本不存在", details={"version_id": version_id})
        if (
            actor.institution_id != version.institution_id
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
        ):
            raise PermissionDeniedError("不能查看其他机构证据的有效期")
        expiry = self.repo.get_expiry(version_id)
        if expiry is None:
            raise NotFoundError("该版本尚未登记有效期")
        return self._expiry_dict(expiry)

    # -------------------------------------------------------------- 巡检
    def run_inspection(
        self,
        actor: User | None,
        *,
        warning_days: int = 30,
        institution_id: str | None = None,
        note: str = "",
        idempotency_key: str | None = None,
    ) -> dict:
        if actor is not None:
            require_roles(actor, Role.QUALITY_AUTHORITY, Role.INSTITUTION_ADMIN)
            is_authority = actor.has_role(Role.QUALITY_AUTHORITY)
            if not is_authority:
                if institution_id is not None and institution_id != actor.institution_id:
                    raise PermissionDeniedError("只能巡检本机构证据")
                # 机构管理员只能巡检本机构
                institution_id = actor.institution_id
        if not isinstance(warning_days, int) or warning_days <= 0:
            raise ValidationError("预警天数必须为正整数")
        scope = institution_id

        def work() -> dict:
            now = self.clock.now_utc()
            as_of_iso = now.isoformat()
            horizon_iso = (now + timedelta(days=warning_days)).isoformat()
            batch_id = self.ids.new_id("insp")
            batch = InspectionBatch(
                batch_id=batch_id,
                run_at=as_of_iso,
                as_of=as_of_iso,
                horizon=horizon_iso,
                warning_days=warning_days,
                institution_id=scope,
                note=note,
            )
            self.repo.insert_inspection_batch(batch)

            expiring, expired = self.repo.list_expiry_candidates(
                as_of_iso, horizon_iso, scope
            )
            new_count = 0
            new_count += self._process_candidates(
                batch_id, as_of_iso, now,
                expiring, InspectionCategory.EXPIRING,
            )
            new_count += self._process_candidates(
                batch_id, as_of_iso, now,
                expired, InspectionCategory.EXPIRED,
            )

            self.repo.update_inspection_counts(
                batch_id,
                expiring_count=len(expiring),
                expired_count=len(expired),
                new_reminder_count=new_count,
            )
            if actor is not None:
                self.audit(
                    actor.user_id, "inspection.run",
                    institution_id=scope,
                    detail={
                        "batch_id": batch_id,
                        "warning_days": warning_days,
                        "expiring": len(expiring),
                        "expired": len(expired),
                        "new_reminders": new_count,
                    },
                )
            view = self._batch_view(
                self.repo.get_inspection_batch(batch_id)
            )
            view["replayed"] = False
            return view

        return self.idempotent(idempotency_key, work)

    def _process_candidates(
        self,
        batch_id: str,
        as_of_iso: str,
        now,
        candidates: list[ExpiryCandidate],
        category: InspectionCategory,
    ) -> int:
        """为一批候选登记提醒（唯一键去重）并记录本批次命中；返回新增提醒数。"""
        new_count = 0
        for cand in candidates:
            expiry = cand.expiry
            key = self.reminder_key(category, expiry.version_id, expiry.valid_until)
            days = _days_between(now, expiry.valid_until, category)
            existing = self.repo.get_reminder(key)
            if existing is None:
                finding = InspectionFinding(
                    finding_id=self.ids.new_id("fnd"),
                    batch_id=batch_id,
                    reminder_key=key,
                    category=category.value,
                    version_id=expiry.version_id,
                    material_id=expiry.material_id,
                    institution_id=expiry.institution_id,
                    valid_until=expiry.valid_until,
                    days_remaining=days,
                    kind=cand.kind,
                    title=cand.title,
                    sensitivity=cand.sensitivity,
                    first_seen_batch_id=batch_id,
                    first_seen_at=as_of_iso,
                    created_at=as_of_iso,
                )
                # UNIQUE(reminder_key) + INSERT OR IGNORE 兜底并发
                if self.repo.insert_inspection_finding(finding):
                    new_count += 1
            # 无论新增还是重复巡检，都记录本批次命中（历史巡检结果可查）
            self.repo.record_inspection_hit(key, batch_id, as_of_iso, days)
        return new_count

    # -------------------------------------------------------------- 查询
    def get_batch_view(self, actor: User, batch_id: str) -> dict:
        require_user(actor)
        batch = self.repo.get_inspection_batch(batch_id)
        if batch is None:
            raise NotFoundError("巡检批次不存在", details={"batch_id": batch_id})
        if (
            batch.institution_id is not None
            and actor.institution_id != batch.institution_id
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
        ):
            raise PermissionDeniedError("不能查看其他机构的巡检批次")
        return self._batch_view(batch)

    def build_batch_view(self, batch_id: str) -> dict:
        batch = self.repo.get_inspection_batch(batch_id)
        if batch is None:
            raise NotFoundError("巡检批次不存在", details={"batch_id": batch_id})
        return self._batch_view(batch)

    def _batch_view(self, batch: InspectionBatch) -> dict:
        expiring = [
            self._finding_dict(f)
            for f in self.repo.list_findings_by_batch(
                batch.batch_id, InspectionCategory.EXPIRING.value
            )
        ]
        expired = [
            self._finding_dict(f)
            for f in self.repo.list_findings_by_batch(
                batch.batch_id, InspectionCategory.EXPIRED.value
            )
        ]
        return {
            "batch_id": batch.batch_id,
            "run_at": batch.run_at,
            "as_of": batch.as_of,
            "horizon": batch.horizon,
            "warning_days": batch.warning_days,
            "institution_id": batch.institution_id,
            "expiring_count": batch.expiring_count,
            "expired_count": batch.expired_count,
            "new_reminder_count": batch.new_reminder_count,
            "note": batch.note,
            "expiring": expiring,
            "expired": expired,
        }

    def list_batches(self, actor: User, limit: int = 50) -> dict:
        require_user(actor)
        scoped = (
            actor.institution_id
            if not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
            else None
        )
        batches = [
            {
                "batch_id": b.batch_id,
                "run_at": b.run_at,
                "as_of": b.as_of,
                "warning_days": b.warning_days,
                "institution_id": b.institution_id,
                "expiring_count": b.expiring_count,
                "expired_count": b.expired_count,
                "new_reminder_count": b.new_reminder_count,
                "note": b.note,
            }
            for b in self.repo.list_inspection_batches(limit)
            if scoped is None or b.institution_id in (scoped, None)
        ]
        return {"batches": batches}

    # -------------------------------------------------------------- 辅助
    @staticmethod
    def reminder_key(category: InspectionCategory, version_id: str, valid_until: str) -> str:
        return f"{category.value}:{version_id}:{valid_until}"

    @staticmethod
    def _resolve_valid_until(local_iso: str, tz_name: str | None) -> str:
        try:
            from datetime import datetime

            parsed = datetime.fromisoformat(local_iso)
        except ValueError as exc:
            raise ValidationError(f"无法解析有效期时刻: {local_iso}") from exc
        if parsed.tzinfo is None and not tz_name:
            raise ValidationError("缺少时区信息：请提供 valid_until_timezone")
        try:
            return resolve_deadline(local_iso, tz_name or "UTC").at_utc_iso
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

    @staticmethod
    def _expiry_dict(e: EvidenceExpiry) -> dict:
        return {
            "version_id": e.version_id,
            "material_id": e.material_id,
            "institution_id": e.institution_id,
            "valid_until": e.valid_until,
            "set_by": e.set_by,
            "set_at": e.set_at,
            "source": e.source,
            "note": e.note,
        }

    @staticmethod
    def _finding_dict(f: InspectionFinding) -> dict:
        return {
            "reminder_key": f.reminder_key,
            "category": f.category,
            "version_id": f.version_id,
            "material_id": f.material_id,
            "institution_id": f.institution_id,
            "valid_until": f.valid_until,
            "days_remaining": f.days_remaining,
            "kind": f.kind,
            "title": f.title,
            "sensitivity": f.sensitivity,
            "first_seen_batch_id": f.first_seen_batch_id,
            "first_seen_at": f.first_seen_at,
        }


def _days_between(now, valid_until_iso: str, category: InspectionCategory) -> int:
    """剩余整天数：即将过期为非负整数，已过期为负整数（超过 24h 即 -1）。"""
    from datetime import datetime

    valid_until = datetime.fromisoformat(valid_until_iso)
    delta = valid_until - now
    days = delta.days
    if category is InspectionCategory.EXPIRING:
        return max(days, 0)
    return min(days, 0)
