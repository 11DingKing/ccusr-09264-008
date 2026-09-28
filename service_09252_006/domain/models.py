"""领域实体（贫血数据载体，业务规则在领域服务/应用服务中）。

时间一律以带时区的 UTC ISO-8601 字符串存储；截止时间同时保存原始
IANA 时区用于展示，比较时统一换化为 UTC 时刻，从而正确处理跨时区截止。
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Optional

from .enums import (
    Decision,
    MaterialKind,
    PackageStatus,
    RequestStatus,
    Role,
    Sensitivity,
    Verdict,
)


@dataclass
class User:
    user_id: str
    institution_id: Optional[str]  # 机构用户非空；权威机构/审计可为空
    roles: tuple[str, ...]
    display_name: str = ""

    def has_role(self, role: Role | str) -> bool:
        wanted = role.value if isinstance(role, Role) else role
        return wanted in self.roles


@dataclass
class Material:
    """逻辑材料（课程大纲、师资、考核、企业反馈中的某一份）。"""

    material_id: str
    institution_id: str
    kind: str                      # MaterialKind
    sensitivity: str               # Sensitivity
    title: str
    current_version_id: Optional[str]
    withdrawn: bool
    created_at: str


@dataclass
class MaterialVersion:
    """材料的一次不可变版本。字节内容按 sha256 内容寻址、去重存储。"""

    version_id: str
    material_id: str
    institution_id: str
    sha256: str
    size: int
    media_type: str
    version_no: int
    supersedes_version_id: Optional[str]
    created_by: str
    created_at: str
    withdrawn: bool                # 该版本是否已撤回
    valid_until: Optional[str] = None  # 证据有效期截止时刻（UTC）；None 表示长期有效


@dataclass
class ValidityCandidate:
    """巡检查询返回的当前版本行（材料 + 当前版本的有效期信息）。"""

    material_id: str
    institution_id: str
    kind: str
    title: str
    version_id: str
    valid_until: str


@dataclass
class PackageEntry:
    """评审包对材料【具体版本】的固定引用。"""

    entry_id: str
    package_id: str
    material_id: str
    version_id: str
    sha256: str
    kind: str
    sensitivity: str
    added_at: str


@dataclass
class ReviewPackage:
    package_id: str
    institution_id: str
    title: str
    status: str                    # PackageStatus
    created_by: str
    created_at: str
    sealed_at: Optional[str]
    manifest_fingerprint: Optional[str]
    decided_at: Optional[str]
    decision: Optional[str]        # Decision
    decision_note: Optional[str]
    review_fingerprint: Optional[str]
    supersedes_package_id: Optional[str]  # 后补材料触发的复审包指向前序包
    entries: list[PackageEntry] = field(default_factory=list)

    def is_mutable(self) -> bool:
        return self.status == PackageStatus.DRAFT.value


@dataclass
class ReviewRequest:
    request_id: str
    package_id: str
    institution_id: str
    reviewer_id: str
    status: str                    # RequestStatus
    assigned_by: str
    assigned_at: str
    responded_at: Optional[str]
    completed_at: Optional[str]
    verdict: Optional[str]         # Verdict
    comment: Optional[str]
    deadline_at_utc: Optional[str]  # 截止时刻（UTC）
    deadline_timezone: Optional[str]  # 原始 IANA 时区，仅展示用


@dataclass
class Objection:
    objection_id: str
    request_id: str
    package_id: str
    institution_id: str
    reviewer_id: str
    category: str
    detail: str
    created_at: str


@dataclass
class Blob:
    sha256: str
    data: bytes
    media_type: str
    created_at: str


@dataclass
class AuditEntry:
    audit_id: str
    package_id: Optional[str]
    institution_id: Optional[str]
    actor_id: str
    action: str
    at: str
    detail: dict = field(default_factory=dict)


@dataclass
class InspectionBatch:
    """一次证据有效期巡检批次（结果快照，历史巡检长期可查）。"""

    batch_id: str
    inspected_at: str               # 巡检时刻（UTC）
    window_days: int                # “即将过期”窗口
    expiring_count: int
    expired_count: int
    reminded_count: int             # 本次新生成的提醒数（重复键被抑制）
    idempotency_key: Optional[str] = None


@dataclass
class InspectionFinding:
    """批次内的一条巡检结果。category 取 expiring / expired。"""

    finding_id: str
    batch_id: str
    category: str                   # InspectionCategory
    material_id: str
    institution_id: str
    kind: str
    title: str
    version_id: str
    valid_until: str                # 有效期截止（UTC ISO）
    days_remaining: Optional[int]   # 距过期整天数；已过期为负/0
    reminder_key: str               # 去重提醒键 category:version_id
    reminded: bool                  # 本次是否新生成提醒（False=键已存在被抑制）
    reminded_at: Optional[str]      # 该提醒首次生成时刻
    created_at: str


def asdict(obj) -> dict:
    return dataclasses.asdict(obj)
