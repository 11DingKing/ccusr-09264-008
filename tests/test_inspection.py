"""证据有效期巡检：两类清单、提醒去重、幂等批次、历史可查。"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
import unittest

from service_09252_006.application.container import ApplicationContext
from service_09252_006.application.ports import FixedClock, Uuid4IdGenerator
from service_09252_006.domain.enums import MaterialKind, Role
from service_09252_006.domain.errors import PermissionDeniedError
from tests.support import Harness, START

import concurrent.futures

ISO = "%Y-%m-%dT%H:%M:%S+00:00"


def iso_at(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(ISO)


class InspectionTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.authority = self.h.user(
            "authority", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.submitter = self.h.user("submit-a", Role.INSTITUTION_SUBMITTER)

    def tearDown(self) -> None:
        self.h.close()

    def material_with_validity(
        self, actor, valid_until: str | None, *, data: bytes | None = None,
        title: str = "材料", withdrawn_material: bool = False,
    ):
        m = self.h.ctx.evidence.register_material(
            actor, kind=MaterialKind.SYLLABUS.value, title=title
        )
        v = self.h.ctx.evidence.upload_version(
            actor,
            material_id=m["material_id"],
            data=data or f"data-{m['material_id']}".encode(),
            valid_until_iso=valid_until,
        )
        if withdrawn_material:
            self.h.ctx.evidence.withdraw_material(
                actor, material_id=m["material_id"]
            )
        return m, v


class ClassificationTests(InspectionTestBase):
    def test_finds_expiring_and_expired_separately(self) -> None:
        now = START
        expiring_due = iso_at(now + timedelta(days=10))
        expired_due = iso_at(now - timedelta(days=2))
        far_due = iso_at(now + timedelta(days=100))       # 窗口外
        boundary_expired = iso_at(now)                     # 恰好等于 now
        boundary_expiring = iso_at(now + timedelta(days=30))  # 恰好窗口边界

        self.material_with_validity(self.admin, expiring_due, title="即将过期")
        self.material_with_validity(self.admin, expired_due, title="已过期")
        self.material_with_validity(self.admin, far_due, title="窗口外")
        self.material_with_validity(self.admin, None, title="长期有效")
        self.material_with_validity(
            self.admin, boundary_expired, data=b"b1", title="恰好过期边界"
        )
        self.material_with_validity(
            self.admin, boundary_expiring, data=b"b2", title="窗口边界"
        )

        result = self.h.ctx.inspections.run_inspection(
            self.authority, window_days=30
        )
        self.assertEqual(result["expiring_count"], 2)
        self.assertEqual(result["expired_count"], 2)
        self.assertEqual(result["reminded_count"], 4)

        # 分别读取两类清单
        expiring = self.h.ctx.inspections.list_findings(
            self.authority, result["batch_id"], "expiring"
        )["findings"]
        expired = self.h.ctx.inspections.list_findings(
            self.authority, result["batch_id"], "expired"
        )["findings"]
        self.assertEqual({f["title"] for f in expiring}, {"即将过期", "窗口边界"})
        self.assertEqual({f["title"] for f in expired}, {"已过期", "恰好过期边界"})
        self.assertTrue(all(f["reminded"] for f in expiring + expired))
        # 所有 expiring 的剩余天数 >=0 且 <=30
        self.assertTrue(all(0 <= f["days_remaining"] <= 30 for f in expiring))
        self.assertTrue(all(f["days_remaining"] <= 0 for f in expired))

    def test_withdrawn_material_and_version_skipped(self) -> None:
        _, v_expired = self.material_with_validity(
            self.admin, iso_at(START - timedelta(days=1)), data=b"x1",
            title="已撤回版本",
        )
        self.h.ctx.evidence.withdraw_version(
            self.admin, version_id=v_expired["version_id"]
        )
        self.material_with_validity(
            self.admin, iso_at(START - timedelta(days=1)), data=b"x2",
            title="已撤回材料", withdrawn_material=True,
        )
        self.material_with_validity(
            self.admin, iso_at(START - timedelta(days=1)), data=b"x3",
            title="仍有效材料",
        )

        result = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertEqual(result["expired_count"], 1)
        self.assertEqual(result["expiring_count"], 0)
        self.assertEqual(result["expired"][0]["title"], "仍有效材料")

    def test_only_current_version_is_inspected(self) -> None:
        m = self.h.ctx.evidence.register_material(
            self.admin, kind=MaterialKind.SYLLABUS.value, title="会续期的材料"
        )
        v1 = self.h.ctx.evidence.upload_version(
            self.admin, material_id=m["material_id"], data=b"v1",
            valid_until_iso=iso_at(START - timedelta(days=1)),
        )
        # 新版本长期有效：当前版本不再是过期版本
        v2 = self.h.ctx.evidence.upload_version(
            self.admin, material_id=m["material_id"], data=b"v2",
        )
        result = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertEqual(result["expired"], [])
        self.assertEqual(result["expiring"], [])

        # 新版本又设了临近有效期
        v3 = self.h.ctx.evidence.upload_version(
            self.admin, material_id=m["material_id"], data=b"v3",
            valid_until_iso=iso_at(START + timedelta(days=5)),
        )
        result = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertEqual(len(result["expiring"]), 1)
        self.assertEqual(result["expiring"][0]["version_id"], v3["version_id"])
        self.assertNotEqual(v1["version_id"], v3["version_id"])

    def test_local_time_requires_timezone(self) -> None:
        m = self.h.ctx.evidence.register_material(
            self.admin, kind=MaterialKind.SYLLABUS.value, title="t"
        )
        with self.assertRaises(Exception):
            self.h.ctx.evidence.upload_version(
                self.admin, material_id=m["material_id"], data=b"d",
                valid_until_iso="2026-10-01T09:00",
            )
        v = self.h.ctx.evidence.upload_version(
            self.admin, material_id=m["material_id"], data=b"d2",
            valid_until_iso="2026-09-26T09:00",
            valid_until_timezone="Asia/Shanghai",
        )
        # 上海 09:00 == UTC 01:00，恰好在 30 天窗口内
        self.assertEqual(v["valid_until"], "2026-09-26T01:00:00+00:00")
        result = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertEqual(len(result["expiring"]), 1)


class ReminderDedupTests(InspectionTestBase):
    def test_repeated_inspection_does_not_remind_again(self) -> None:
        self.material_with_validity(
            self.admin, iso_at(START + timedelta(days=10)),
            data=b"e1", title="即将过期",
        )
        self.material_with_validity(
            self.admin, iso_at(START - timedelta(days=3)),
            data=b"e2", title="已过期",
        )

        first = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertEqual(first["reminded_count"], 2)

        # 同一时刻重复巡检：不产生新提醒，但结果快照照常落库
        second = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertNotEqual(first["batch_id"], second["batch_id"])
        self.assertEqual(second["expiring_count"], 1)
        self.assertEqual(second["expired_count"], 1)
        self.assertEqual(second["reminded_count"], 0)
        for finding in second["expiring"] + second["expired"]:
            self.assertFalse(finding["reminded"])
            self.assertEqual(
                finding["reminded_at"], first["inspected_at"]
            )

    def test_category_transition_keys_are_distinct(self) -> None:
        """同一版本从“即将过期”转为“已过期”：两类提醒键各自只生成一次。"""
        self.material_with_validity(
            self.admin, iso_at(START + timedelta(days=10)),
            data=b"e", title="过渡证据",
        )
        r1 = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertEqual(r1["reminded_count"], 1)
        self.assertEqual(r1["expiring_count"], 1)

        self.h.clock.advance(days=20)
        r2 = self.h.ctx.inspections.run_inspection(self.authority)
        # 此时已过期：expired 键第一次出现 -> 仍有 1 条新提醒
        self.assertEqual(r2["expired_count"], 1)
        self.assertEqual(r2["expiring_count"], 0)
        self.assertEqual(r2["reminded_count"], 1)
        self.assertEqual(r2["expired"][0]["reminder_key"],
                         f"expired:{r1['expiring'][0]['version_id']}")

        self.h.clock.advance(days=5)
        r3 = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertEqual(r3["reminded_count"], 0)
        self.assertEqual(r3["expired_count"], 1)
        self.assertFalse(r3["expired"][0]["reminded"])


class IdempotencyTests(InspectionTestBase):
    def test_same_idempotency_key_replays_batch(self) -> None:
        self.material_with_validity(
            self.admin, iso_at(START + timedelta(days=10)), data=b"e"
        )
        r1 = self.h.ctx.inspections.run_inspection(
            self.authority, idempotency_key="weekly-2026w39"
        )
        r2 = self.h.ctx.inspections.run_inspection(
            self.authority, idempotency_key="weekly-2026w39"
        )
        self.assertTrue(r2["replayed"])
        self.assertEqual(r1["batch_id"], r2["batch_id"])

        batches = self.h.ctx.inspections.list_batches(self.authority)["batches"]
        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0]["batch_id"], r1["batch_id"])

    def test_rerun_from_separate_process_is_idempotent(self) -> None:
        """模拟 Python 重复执行：新进程/新连接打开同一 SQLite 文件。"""
        self.material_with_validity(
            self.admin, iso_at(START + timedelta(days=10)), data=b"e"
        )
        r1 = self.h.ctx.inspections.run_inspection(self.authority)

        ctx2 = ApplicationContext(
            self.h.db_path, clock=self.h.clock, ids=Uuid4IdGenerator()
        )
        try:
            r2 = ctx2.inspections.run_inspection(self.authority)
        finally:
            ctx2.close()
        self.assertNotEqual(r1["batch_id"], r2["batch_id"])
        self.assertEqual(r2["reminded_count"], 0)
        self.assertEqual(len(r2["expiring"]), 1)
        self.assertFalse(r2["expiring"][0]["reminded"])


class HistoryTests(InspectionTestBase):
    def test_history_batches_and_findings_remain_queryable(self) -> None:
        self.material_with_validity(
            self.admin, iso_at(START + timedelta(days=10)), data=b"e"
        )
        r1 = self.h.ctx.inspections.run_inspection(self.authority)
        self.h.clock.advance(days=40)
        r2 = self.h.ctx.inspections.run_inspection(self.authority)  # 此时已过期

        listing = self.h.ctx.inspections.list_batches(self.authority)["batches"]
        self.assertEqual([b["batch_id"] for b in listing],
                         [r2["batch_id"], r1["batch_id"]])

        old = self.h.ctx.inspections.get_batch(self.authority, r1["batch_id"])
        self.assertEqual(old["expiring_count"], 1)
        self.assertEqual(old["expired_count"], 0)
        self.assertEqual(len(old["expiring"]), 1)
        # 历史批次结果不随后续状态变化而改变
        self.assertEqual(
            old["expiring"][0]["version_id"], r1["expiring"][0]["version_id"]
        )

        new = self.h.ctx.inspections.get_batch(self.authority, r2["batch_id"])
        self.assertEqual(new["expired_count"], 1)
        self.assertEqual(new["expiring_count"], 0)

        # 按类别分别读取
        only_expired = self.h.ctx.inspections.list_findings(
            self.authority, r2["batch_id"], "expired"
        )["findings"]
        only_expiring = self.h.ctx.inspections.list_findings(
            self.authority, r2["batch_id"], "expiring"
        )["findings"]
        self.assertEqual(len(only_expired), 1)
        self.assertEqual(only_expiring, [])


class PermissionTests(InspectionTestBase):
    def test_only_authority_and_auditor_may_run(self) -> None:
        self.material_with_validity(
            self.admin, iso_at(START + timedelta(days=10)), data=b"e"
        )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.inspections.run_inspection(self.submitter)
        reviewer = self.h.user("rev", Role.REVIEWER, institution_id=None)
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.inspections.run_inspection(reviewer)

        auditor = self.h.user("aud", Role.AUDITOR, institution_id=None)
        result = self.h.ctx.inspections.run_inspection(auditor)
        self.assertEqual(result["expiring_count"], 1)

    def test_institution_scope_is_enforced(self) -> None:
        admin_b = self.h.user(
            "admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b"
        )
        self.material_with_validity(
            self.admin, iso_at(START - timedelta(days=1)), data=b"a"
        )
        m = self.h.ctx.evidence.register_material(
            admin_b, kind=MaterialKind.SYLLABUS.value, title="b 机构材料"
        )
        self.h.ctx.evidence.upload_version(
            admin_b, material_id=m["material_id"], data=b"b",
            valid_until_iso=iso_at(START - timedelta(days=1)),
        )
        all_res = self.h.ctx.inspections.run_inspection(self.authority)
        self.assertEqual(all_res["expired_count"], 2)

        scoped = self.h.ctx.inspections.run_inspection(
            self.authority, institution_id="inst-b"
        )
        self.assertEqual(scoped["expired_count"], 1)
        self.assertEqual(scoped["expired"][0]["institution_id"], "inst-b")


class ConcurrentInspectionTests(InspectionTestBase):
    """多连接（模拟多进程 worker）同时巡检：提醒键恰好只生成一次。"""

    def _worker(self) -> dict:
        ctx = ApplicationContext(
            self.h.db_path, clock=FixedClock(START), ids=Uuid4IdGenerator()
        )
        try:
            authority = ctx.repo.get_user("authority")
            return ctx.inspections.run_inspection(authority)
        finally:
            ctx.close()

    def test_concurrent_runs_remind_exactly_once(self) -> None:
        for i in range(5):
            self.material_with_validity(
                self.admin, iso_at(START - timedelta(days=i + 1)),
                data=f"past-{i}".encode(), title=f"过期-{i}",
            )
        for i in range(5):
            self.material_with_validity(
                self.admin, iso_at(START + timedelta(days=i + 1)),
                data=f"soon-{i}".encode(), title=f"临期-{i}",
            )

        errors: list[Exception] = []
        results: list[dict] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(self._worker) for _ in range(8)]
            for fut in concurrent.futures.as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        # 每个并发批次都完整记录 10 条结果
        self.assertTrue(all(r["expired_count"] == 5 for r in results))
        self.assertTrue(all(r["expiring_count"] == 5 for r in results))
        # 但 8 次巡检合计只生成 10 条提醒（恰好一次），无 OperationalError
        self.assertEqual(sum(r["reminded_count"] for r in results), 10)

        # 库里确实只有 10 个提醒键，8 个批次
        n_reminders = self.h.repo._conn.execute(
            "SELECT COUNT(*) FROM inspection_reminders"
        ).fetchone()[0]
        n_batches = self.h.repo._conn.execute(
            "SELECT COUNT(*) FROM inspection_batches"
        ).fetchone()[0]
        self.assertEqual(n_reminders, 10)
        self.assertEqual(n_batches, 8)


class CliInspectionTests(unittest.TestCase):
    """CLI 子命令端到端：真实子进程重复执行必须幂等。"""

    def setUp(self) -> None:
        now = datetime.now(timezone.utc)
        self.now = now
        self.h = Harness(moment=now)
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        m1 = self.h.ctx.evidence.register_material(
            self.admin, kind=MaterialKind.SYLLABUS.value, title="即将过期"
        )
        self.h.ctx.evidence.upload_version(
            self.admin, material_id=m1["material_id"], data=b"soon",
            valid_until_iso=iso_at(now + timedelta(days=10)),
        )
        m2 = self.h.ctx.evidence.register_material(
            self.admin, kind=MaterialKind.SYLLABUS.value, title="已过期"
        )
        self.h.ctx.evidence.upload_version(
            self.admin, material_id=m2["material_id"], data=b"past",
            valid_until_iso=iso_at(now - timedelta(days=10)),
        )
        self.h.ctx.close()

    def tearDown(self) -> None:
        self.h.close()

    def _run_cli(self) -> dict:
        proc = subprocess.run(
            [
                sys.executable, "-m", "service_09252_006.cli", "inspect",
                "--db", self.h.db_path, "--json",
            ],
            capture_output=True, text=True, check=True,
        )
        return json.loads(proc.stdout)

    def test_cli_repeat_runs_suppress_reminders(self) -> None:
        first = self._run_cli()
        self.assertEqual(first["expiring_count"], 1)
        self.assertEqual(first["expired_count"], 1)
        self.assertEqual(first["reminded_count"], 2)

        second = self._run_cli()
        self.assertEqual(second["expiring_count"], 1)
        self.assertEqual(second["expired_count"], 1)
        self.assertEqual(second["reminded_count"], 0)
        self.assertNotEqual(first["batch_id"], second["batch_id"])
        self.assertFalse(second["expiring"][0]["reminded"])

        third = self._run_cli()
        self.assertEqual(third["reminded_count"], 0)


if __name__ == "__main__":
    unittest.main()
