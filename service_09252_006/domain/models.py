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
class EvidenceExpiry:
    """证据版本的有效期登记（一个版本至多一条，可续期为更晚时刻）。"""

    version_id: str                 # 主键，1:1 指向 versions
    material_id: str
    institution_id: str
    valid_until: str                # 失效时刻，UTC ISO-8601 绝对时刻
    set_by: str
    set_at: str
    source: str = ""                # 登记依据/来源说明
    note: str = ""


@dataclass
class ExpiryCandidate:
    """巡检扫描命中的一行：有效期信息 + 材料展示字段。"""

    expiry: EvidenceExpiry
    kind: str
    title: str
    sensitivity: str


@dataclass
class InspectionBatch:
    """一次证据有效期巡检批次；历史批次永久保留、随时可查。"""

    batch_id: str
    run_at: str                     # 巡检执行时刻（UTC ISO）
    as_of: str                      # 判定基准时刻（UTC ISO）
    horizon: str                    # 即将过期窗口终点（UTC ISO）
    warning_days: int
    institution_id: Optional[str]   # 非空表示本批次仅巡检该机构
    expiring_count: int = 0
    expired_count: int = 0
    new_reminder_count: int = 0
    note: str = ""


@dataclass
class InspectionFinding:
    """巡检发现项（即将过期/已过期各一条提醒）。

    reminder_key 全局唯一：同一份证据在同一有效期下，重复巡检只生成一次
    提醒；续期后产生新的即将过期键，已过期键每版本仅一次。
    """

    finding_id: str
    batch_id: str
    reminder_key: str
    category: str                   # InspectionCategory: expiring | expired
    version_id: str
    material_id: str
    institution_id: str
    valid_until: str
    days_remaining: int             # 即将过期为正/零，已过期为负
    kind: str
    title: str
    sensitivity: str
    first_seen_batch_id: str        # 该提醒首次出现的批次（可能早于本批次）
    first_seen_at: str
    created_at: str


def asdict(obj) -> dict:
    return dataclasses.asdict(obj)
