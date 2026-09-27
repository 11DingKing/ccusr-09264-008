"""仓库抽象端口。

应用服务只依赖此接口；SQLite 实现见 persistence 层。所有涉及多步
状态推进的用例必须在 transaction() 上下文中完成，以保证并发复审下
的可串行化与崩溃可恢复。
"""
from __future__ import annotations

import abc
from contextlib import AbstractContextManager

from ..domain.models import (
    AuditEntry,
    Blob,
    EvidenceExpiry,
    ExpiryCandidate,
    InspectionBatch,
    InspectionFinding,
    Material,
    MaterialVersion,
    Objection,
    PackageEntry,
    ReviewPackage,
    ReviewRequest,
    User,
)


class Repository(abc.ABC):
    # ---- 事务/生命周期 ----
    @abc.abstractmethod
    def transaction(self) -> AbstractContextManager[None]:
        """串行写事务（SQLite 实现为 BEGIN IMMEDIATE）。"""

    @abc.abstractmethod
    def close(self) -> None: ...

    # ---- 用户/角色 ----
    @abc.abstractmethod
    def upsert_user(self, user: User) -> None: ...

    @abc.abstractmethod
    def get_user(self, user_id: str) -> User | None: ...

    @abc.abstractmethod
    def put_token(self, token: str, user_id: str, at: str) -> None: ...

    @abc.abstractmethod
    def get_user_by_token(self, token: str) -> User | None: ...

    # ---- 幂等键 ----
    @abc.abstractmethod
    def get_idempotent_result(self, key: str) -> dict | None: ...

    @abc.abstractmethod
    def save_idempotent_result(self, key: str, result: dict) -> None: ...

    # ---- 材料与版本 ----
    @abc.abstractmethod
    def put_blob(self, blob: Blob) -> None: ...

    @abc.abstractmethod
    def get_blob(self, sha256: str) -> Blob | None: ...

    @abc.abstractmethod
    def insert_material(self, material: Material) -> None: ...

    @abc.abstractmethod
    def get_material(self, material_id: str) -> Material | None: ...

    @abc.abstractmethod
    def insert_version(self, version: MaterialVersion) -> None: ...

    @abc.abstractmethod
    def get_version(self, version_id: str) -> MaterialVersion | None: ...

    @abc.abstractmethod
    def find_version_by_digest(
        self, material_id: str, sha256: str
    ) -> MaterialVersion | None: ...

    @abc.abstractmethod
    def list_versions(self, material_id: str) -> list[MaterialVersion]: ...

    @abc.abstractmethod
    def mark_version_withdrawn(
        self, version_id: str, withdrawn: bool, at: str
    ) -> bool: ...

    @abc.abstractmethod
    def mark_material_withdrawn(
        self, material_id: str, withdrawn: bool
    ) -> bool: ...

    # ---- 评审包 ----
    @abc.abstractmethod
    def insert_package(self, package: ReviewPackage) -> None: ...

    @abc.abstractmethod
    def get_package(self, package_id: str) -> ReviewPackage | None: ...

    @abc.abstractmethod
    def list_packages(
        self, institution_id: str | None = None,
    ) -> list[ReviewPackage]: ...

    @abc.abstractmethod
    def insert_entry(self, entry: PackageEntry) -> None: ...

    @abc.abstractmethod
    def entry_exists(self, package_id: str, version_id: str) -> bool: ...

    @abc.abstractmethod
    def transition_package_status(
        self,
        package_id: str,
        expected_status: str,
        new_status: str,
        **fields,
    ) -> bool:
        """条件更新；状态不再是 expected_status 时返回 False（并发冲突）。"""

    # ---- 评审请求 ----
    @abc.abstractmethod
    def insert_request(self, request: ReviewRequest) -> None: ...

    @abc.abstractmethod
    def get_request(self, request_id: str) -> ReviewRequest | None: ...

    @abc.abstractmethod
    def list_requests_by_package(self, package_id: str) -> list[ReviewRequest]: ...

    @abc.abstractmethod
    def list_active_requests_by_reviewer(self, reviewer_id: str) -> list[ReviewRequest]:
        """状态属于 pending/accepted/completed 的请求（权限变化依据）。"""

    @abc.abstractmethod
    def update_request(self, request: ReviewRequest) -> None: ...

    # ---- 异议 ----
    @abc.abstractmethod
    def insert_objection(self, objection: Objection) -> None: ...

    @abc.abstractmethod
    def list_objections_by_package(self, package_id: str) -> list[Objection]: ...

    # ---- 审计 ----
    @abc.abstractmethod
    def insert_audit(self, entry: AuditEntry) -> None: ...

    @abc.abstractmethod
    def list_audit(
        self, package_id: str | None = None, limit: int = 200
    ) -> list[AuditEntry]: ...

    # ---- 证据有效期 ----
    @abc.abstractmethod
    def upsert_expiry(self, expiry: EvidenceExpiry) -> None:
        """登记或续期一个版本的有效期（1:1）。"""

    @abc.abstractmethod
    def get_expiry(self, version_id: str) -> EvidenceExpiry | None: ...

    @abc.abstractmethod
    def list_expiry_candidates(
        self, as_of_iso: str, horizon_iso: str, institution_id: str | None = None
    ) -> tuple[list[ExpiryCandidate], list[ExpiryCandidate]]:
        """按基准时刻返回 (即将过期, 已过期) 两类候选。

        仅包含版本/材料均未撤回的证据；即将过期为
        as_of < valid_until <= horizon，已过期为 valid_until <= as_of。
        """

    # ---- 巡检批次与提醒 ----
    @abc.abstractmethod
    def insert_inspection_batch(self, batch: InspectionBatch) -> None: ...

    @abc.abstractmethod
    def update_inspection_counts(
        self,
        batch_id: str,
        *,
        expiring_count: int,
        expired_count: int,
        new_reminder_count: int,
    ) -> None:
        """批次扫描结束后回填清单计数（同一写事务内）。"""

    @abc.abstractmethod
    def get_inspection_batch(self, batch_id: str) -> InspectionBatch | None: ...

    @abc.abstractmethod
    def list_inspection_batches(
        self, limit: int = 50
    ) -> list[InspectionBatch]: ...

    @abc.abstractmethod
    def insert_inspection_finding(self, finding: InspectionFinding) -> bool:
        """插入提醒发现；reminder_key 已存在时返回 False（不重复生成提醒）。"""

    @abc.abstractmethod
    def record_inspection_hit(
        self, reminder_key: str, batch_id: str, as_of_iso: str, days_remaining: int
    ) -> bool:
        """记录提醒在某批次被再次巡检到（同批次重复返回 False）。"""

    @abc.abstractmethod
    def get_reminder(self, reminder_key: str) -> InspectionFinding | None: ...

    @abc.abstractmethod
    def list_findings_by_batch(
        self, batch_id: str, category: str | None = None
    ) -> list[InspectionFinding]: ...

    @abc.abstractmethod
    def count_inspection_findings(self, reminder_key: str) -> int:
        """统计一个提醒键在多少个批次中被重复巡检到（历史可追踪）。"""
