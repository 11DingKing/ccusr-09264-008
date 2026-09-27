"""证据有效期巡检：两类清单、重复巡检幂等、历史可查、续期/撤回、跨进程。"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from service_09252_006.application.container import ApplicationContext
from service_09252_006.application.ports import FixedClock, SequentialIdGenerator
from service_09252_006.domain.enums import MaterialKind, Role
from service_09252_006.domain.errors import (
    PermissionDeniedError,
    ValidationError,
)
from service_09252_006.domain.models import User
from tests.flow import upload_material
from tests.support import Harness, START


def _upload(ctx, actor, data: bytes, title: str = "材料") -> dict:
    m = ctx.evidence.register_material(
        actor, kind=MaterialKind.SYLLABUS.value, title=title
    )
    return ctx.evidence.upload_version(
        actor, material_id=m["material_id"], data=data
    )


class InspectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.admin_b = self.h.user(
            "admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b"
        )
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )

    def tearDown(self) -> None:
        self.h.close()

    def _material_with_expiry(self, valid_in_days: float):
        item = upload_material(
            self.h, self.admin, data=f"doc-{valid_in_days}".encode()
        )
        valid = (START + timedelta(days=valid_in_days)).isoformat()
        self.h.ctx.inspections.set_expiry(
            self.admin,
            version_id=item.version["version_id"],
            valid_until_local_iso=valid,
        )
        return item

    # ------------------------------------------------- 两类清单分别读取
    def test_scan_splits_expiring_and_expired_lists(self) -> None:
        soon = self._material_with_expiry(10)      # 即将过期
        later = self._material_with_expiry(60)     # 窗口外
        past = self._material_with_expiry(-3)      # 已过期

        view = self.h.ctx.inspections.run_inspection(
            self.authority, warning_days=30
        )
        self.assertEqual(view["warning_days"], 30)
        self.assertEqual(view["expiring_count"], 1)
        self.assertEqual(view["expired_count"], 1)

        # 测试分别读取即将过期与已过期清单
        expiring = view["expiring"]
        expired = view["expired"]
        self.assertEqual([f["version_id"] for f in expiring],
                         [soon.version["version_id"]])
        self.assertEqual([f["version_id"] for f in expired],
                         [past.version["version_id"]])
        self.assertNotIn(later.version["version_id"],
                         [f["version_id"] for f in expiring + expired])
        self.assertEqual(expiring[0]["category"], "expiring")
        self.assertEqual(expiring[0]["days_remaining"], 10)
        self.assertEqual(expired[0]["category"], "expired")
        self.assertEqual(expired[0]["days_remaining"], -3)
        self.assertTrue(expiring[0]["reminder_key"].startswith("expiring:"))
        self.assertTrue(expired[0]["reminder_key"].startswith("expired:"))

    def test_boundary_window_is_inclusive_horizon_exclusive_now(self) -> None:
        self._material_with_expiry(30)   # 恰好在窗口终点：计入即将过期
        self._material_with_expiry(0)    # 恰好失效：计入已过期
        view = self.h.ctx.inspections.run_inspection(
            self.authority, warning_days=30
        )
        self.assertEqual(view["expiring_count"], 1)
        self.assertEqual(view["expired_count"], 1)

    # ------------------------------------------------- 重复巡检不重复提醒
    def test_repeated_runs_do_not_duplicate_reminders(self) -> None:
        self._material_with_expiry(10)
        self._material_with_expiry(-2)

        first = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertEqual(first["new_reminder_count"], 2)
        keys_first = {
            f["reminder_key"] for f in first["expiring"] + first["expired"]
        }

        # 时钟推进 5 天后再次巡检：剩余天数变化，但不产生新提醒
        self.h.clock.advance(days=5)
        second = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertNotEqual(first["batch_id"], second["batch_id"])
        self.assertEqual(second["new_reminder_count"], 0)
        self.assertEqual(second["expiring_count"], 1)
        self.assertEqual(second["expired_count"], 1)
        keys_second = {
            f["reminder_key"] for f in second["expiring"] + second["expired"]
        }
        self.assertEqual(keys_first, keys_second)
        # 本批次清单仍可读，且剩余天数已更新
        self.assertEqual(second["expiring"][0]["days_remaining"], 5)
        self.assertEqual(second["expired"][0]["days_remaining"], -7)
        # first_seen 始终指向首个批次
        self.assertEqual(
            second["expiring"][0]["first_seen_batch_id"], first["batch_id"]
        )

        # 全库只有两条提醒
        count = self.h.repo._conn.execute(
            "SELECT COUNT(*) FROM inspection_findings"
        ).fetchone()[0]
        self.assertEqual(count, 2)
        # 两个批次都有命中记录
        hits = self.h.repo._conn.execute(
            "SELECT batch_id, COUNT(*) FROM inspection_hits GROUP BY batch_id"
        ).fetchall()
        self.assertEqual({r[0] for r in hits},
                         {first["batch_id"], second["batch_id"]})

    # ------------------------------------------------- 历史巡检结果可查
    def test_historical_batches_remain_queryable(self) -> None:
        self._material_with_expiry(10)
        first = self.h.ctx.inspections.run_inspection(self.authority)
        self.h.clock.advance(days=5)
        second = self.h.ctx.inspections.run_inspection(self.authority)

        listing = self.h.ctx.inspections.list_batches(self.authority)
        self.assertEqual(
            [b["batch_id"] for b in listing["batches"]],
            [second["batch_id"], first["batch_id"]],  # 新批次在前
        )
        first_again = self.h.ctx.inspections.get_batch_view(
            self.authority, first["batch_id"]
        )
        # 历史批次保留当时的基准时刻与剩余天数
        self.assertEqual(first_again["as_of"], first["as_of"])
        self.assertEqual(first_again["expiring"][0]["days_remaining"], 10)
        second_view = self.h.ctx.inspections.get_batch_view(
            self.authority, second["batch_id"]
        )
        self.assertEqual(second_view["expiring"][0]["days_remaining"], 5)

    def test_idempotency_key_replays_batch(self) -> None:
        self._material_with_expiry(10)
        first = self.h.ctx.inspections.run_inspection(
            self.authority, idempotency_key="weekly-2026w39"
        )
        self.h.clock.advance(days=1)
        replay = self.h.ctx.inspections.run_inspection(
            self.authority, idempotency_key="weekly-2026w39"
        )
        self.assertEqual(replay["batch_id"], first["batch_id"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(len(self.h.repo.list_inspection_batches()), 1)

    # ------------------------------------------------- 续期产生新提醒
    def test_renewal_allows_new_expiring_reminder(self) -> None:
        item = self._material_with_expiry(10)
        first = self.h.ctx.inspections.run_inspection(self.authority)
        old_key = first["expiring"][0]["reminder_key"]

        renewed = self.h.ctx.inspections.set_expiry(
            self.admin,
            version_id=item.version["version_id"],
            valid_until_local_iso=(START + timedelta(days=200)).isoformat(),
            note="已换发新证",
        )
        self.assertTrue(renewed["renewed"])

        # 续期后脱离预警窗口：无即将过期
        view = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertEqual(view["expiring"], [])
        self.assertEqual(view["new_reminder_count"], 0)

        # 临近新失效日时，以新有效期再提醒一次
        self.h.clock.advance(days=180)
        view = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertEqual(view["expiring_count"], 1)
        self.assertEqual(view["new_reminder_count"], 1)
        self.assertNotEqual(view["expiring"][0]["reminder_key"], old_key)

    # ------------------------------------------------- 撤回的证据不巡检
    def test_withdrawn_evidence_excluded(self) -> None:
        item = self._material_with_expiry(5)
        self.h.ctx.evidence.withdraw_version(
            self.admin, version_id=item.version["version_id"]
        )
        view = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertEqual(view["expiring_count"], 0)
        self.assertEqual(view["expiring"], [])

    # ------------------------------------------------- 机构范围与权限
    def test_institution_admin_scoped_to_own_institution(self) -> None:
        self._material_with_expiry(5)
        view = self.h.ctx.inspections.run_inspection(self.admin)
        self.assertEqual(view["institution_id"], "inst-a")
        self.assertEqual(view["expiring_count"], 1)
        # 不能把机构参数改成别的机构
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.inspections.run_inspection(
                self.admin, institution_id="inst-b"
            )
        # B 机构管理员看不到 A 机构批次
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.inspections.get_batch_view(
                self.admin_b, view["batch_id"]
            )
        listing_b = self.h.ctx.inspections.list_batches(self.admin_b)
        self.assertEqual(listing_b["batches"], [])

    def test_expiry_input_requires_timezone_for_naive_datetime(self) -> None:
        item = upload_material(self.h, self.admin, data=b"x")
        with self.assertRaises(ValidationError):
            self.h.ctx.inspections.set_expiry(
                self.admin,
                version_id=item.version["version_id"],
                valid_until_local_iso="2026-10-05T10:00:00",
            )
        # 带 IANA 时区可以，统一存 UTC
        result = self.h.ctx.inspections.set_expiry(
            self.admin,
            version_id=item.version["version_id"],
            valid_until_local_iso="2026-10-05T18:00:00",
            valid_until_timezone="Asia/Shanghai",
        )
        self.assertTrue(result["valid_until"].endswith("+00:00"))


# 跨进程：用两次独立的 Python 解释器执行 CLI 巡检，验证脚本级幂等。
class InspectionProcessTests(unittest.TestCase):
    def test_cli_inspect_is_idempotent_across_processes(self) -> None:
        fd, db_path = tempfile.mkstemp(prefix="qe-inspect-", suffix=".db")
        os.close(fd)
        os.unlink(db_path)
        try:
            now = datetime(2026, 9, 27, 1, 0, tzinfo=timezone.utc)
            ctx = ApplicationContext(
                db_path,
                clock=FixedClock(now),
                ids=SequentialIdGenerator(),
            )
            admin = User(
                user_id="admin-a",
                institution_id="inst-a",
                roles=(Role.INSTITUTION_ADMIN.value,),
                display_name="admin",
            )
            ctx.repo.upsert_user(admin)
            soon = _upload(ctx, admin, b"soon", "即将过期")
            past = _upload(ctx, admin, b"past", "已过期")
            ctx.inspections.set_expiry(
                admin,
                version_id=soon["version_id"],
                valid_until_local_iso=(now + timedelta(days=10)).isoformat(),
            )
            ctx.inspections.set_expiry(
                admin,
                version_id=past["version_id"],
                valid_until_local_iso=(now - timedelta(days=2)).isoformat(),
            )
            ctx.close()

            def run_cli() -> dict:
                proc = subprocess.run(
                    [sys.executable, "-m", "service_09252_006.cli", "inspect",
                     "--db", db_path, "--warning-days", "30", "--json"],
                    check=True, capture_output=True, text=True,
                )
                return json.loads(proc.stdout)

            first = run_cli()
            second = run_cli()
            self.assertEqual(first["new_reminder_count"], 2)
            self.assertEqual(second["new_reminder_count"], 0)
            self.assertNotEqual(first["batch_id"], second["batch_id"])
            first_keys = {
                f["reminder_key"]
                for f in first["expiring"] + first["expired"]
            }
            second_keys = {
                f["reminder_key"]
                for f in second["expiring"] + second["expired"]
            }
            self.assertEqual(first_keys, second_keys)
            self.assertEqual(second["expiring_count"], 1)
            self.assertEqual(second["expired_count"], 1)
        finally:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(db_path + suffix)
                except FileNotFoundError:
                    pass


if __name__ == "__main__":
    unittest.main()
