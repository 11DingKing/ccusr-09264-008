"""SQLite 持久化。

- 写事务使用 BEGIN IMMEDIATE + busy_timeout，多进程/多线程并发复审时
  状态条件更新串行化，失败者收到 ConflictError；
- 幂等键唯一约束保证同一业务键只生效一次；
- 内容字节按 sha256 去重存放，指纹不匹配的写入被拒绝；
- 数据库文件路径由调用方提供（运行数据不进入源码目录）。
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
from typing import Iterator

from ..application.repository import Repository
from ..domain.fingerprint import digest_bytes
from ..domain.models import (
    AuditEntry,
    Blob,
    InspectionBatch,
    InspectionFinding,
    Material,
    MaterialVersion,
    Objection,
    PackageEntry,
    ReviewPackage,
    ReviewRequest,
    User,
    ValidityCandidate,
)

SCHEMA_VERSION = 2


class SqliteRepository(Repository):
    def __init__(self, path: str, *, timeout: float = 30.0) -> None:
        self._path = path
        self._conn = sqlite3.connect(
            path,
            timeout=timeout,
            isolation_level=None,  # 手工管理事务
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(f"PRAGMA busy_timeout = {int(timeout * 1000)}")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._txn_depth = 0
        self._ensure_schema()

    # ---------------------------------------------------------------- schema
    def _ensure_schema(self) -> None:
        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version < 1:
            # executescript 会自行提交事务；把 user_version 写入放在同一脚本
            self._conn.executescript(
                """
                    CREATE TABLE IF NOT EXISTS users (
                        user_id        TEXT PRIMARY KEY,
                        institution_id TEXT,
                        roles_json     TEXT NOT NULL,
                        display_name   TEXT NOT NULL DEFAULT ''
                    );

                    CREATE TABLE IF NOT EXISTS blobs (
                        sha256     TEXT PRIMARY KEY,
                        data       BLOB NOT NULL,
                        media_type TEXT NOT NULL,
                        size       INTEGER NOT NULL,
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS materials (
                        material_id        TEXT PRIMARY KEY,
                        institution_id     TEXT NOT NULL,
                        kind               TEXT NOT NULL,
                        sensitivity        TEXT NOT NULL,
                        title              TEXT NOT NULL,
                        current_version_id TEXT,
                        withdrawn          INTEGER NOT NULL DEFAULT 0,
                        created_at         TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS versions (
                        version_id              TEXT PRIMARY KEY,
                        material_id             TEXT NOT NULL REFERENCES materials(material_id),
                        institution_id          TEXT NOT NULL,
                        sha256                  TEXT NOT NULL,
                        size                    INTEGER NOT NULL,
                        media_type              TEXT NOT NULL,
                        version_no              INTEGER NOT NULL,
                        supersedes_version_id   TEXT,
                        created_by              TEXT NOT NULL,
                        created_at              TEXT NOT NULL,
                        withdrawn               INTEGER NOT NULL DEFAULT 0,
                        withdrawn_at            TEXT,
                        UNIQUE(material_id, version_no)
                    );

                    CREATE TABLE IF NOT EXISTS packages (
                        package_id            TEXT PRIMARY KEY,
                        institution_id        TEXT NOT NULL,
                        title                 TEXT NOT NULL,
                        status                TEXT NOT NULL,
                        created_by            TEXT NOT NULL,
                        created_at            TEXT NOT NULL,
                        sealed_at             TEXT,
                        manifest_fingerprint  TEXT,
                        decided_at            TEXT,
                        decision              TEXT,
                        decision_note         TEXT,
                        review_fingerprint    TEXT,
                        supersedes_package_id TEXT
                    );

                    CREATE TABLE IF NOT EXISTS entries (
                        entry_id    TEXT PRIMARY KEY,
                        package_id  TEXT NOT NULL REFERENCES packages(package_id),
                        material_id TEXT NOT NULL,
                        version_id  TEXT NOT NULL REFERENCES versions(version_id),
                        sha256      TEXT NOT NULL,
                        kind        TEXT NOT NULL,
                        sensitivity TEXT NOT NULL,
                        added_at    TEXT NOT NULL,
                        UNIQUE(package_id, version_id)
                    );

                    CREATE TABLE IF NOT EXISTS requests (
                        request_id       TEXT PRIMARY KEY,
                        package_id       TEXT NOT NULL REFERENCES packages(package_id),
                        institution_id   TEXT NOT NULL,
                        reviewer_id      TEXT NOT NULL,
                        status           TEXT NOT NULL,
                        assigned_by      TEXT NOT NULL,
                        assigned_at      TEXT NOT NULL,
                        responded_at     TEXT,
                        completed_at     TEXT,
                        verdict          TEXT,
                        comment          TEXT,
                        deadline_at_utc  TEXT,
                        deadline_timezone TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_requests_reviewer
                        ON requests(reviewer_id, status);
                    CREATE INDEX IF NOT EXISTS idx_requests_package ON requests(package_id);

                    CREATE TABLE IF NOT EXISTS objections (
                        objection_id  TEXT PRIMARY KEY,
                        request_id    TEXT NOT NULL REFERENCES requests(request_id),
                        package_id    TEXT NOT NULL REFERENCES packages(package_id),
                        institution_id TEXT NOT NULL,
                        reviewer_id   TEXT NOT NULL,
                        category      TEXT NOT NULL,
                        detail        TEXT NOT NULL,
                        created_at    TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS audit_log (
                        audit_id       TEXT PRIMARY KEY,
                        package_id     TEXT,
                        institution_id TEXT,
                        actor_id       TEXT NOT NULL,
                        action         TEXT NOT NULL,
                        at             TEXT NOT NULL,
                        detail_json    TEXT NOT NULL DEFAULT '{}'
                    );

                    CREATE TABLE IF NOT EXISTS idempotency (
                        idempotency_key TEXT PRIMARY KEY,
                        result_json     TEXT NOT NULL,
                        created_at      TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS api_tokens (
                        token       TEXT PRIMARY KEY,
                        user_id     TEXT NOT NULL REFERENCES users(user_id),
                        created_at  TEXT NOT NULL
                    );

                    PRAGMA user_version = 1;
                """
            )
            version = 1
        if version < 2:
            # 证据有效期：版本有效期列 + 巡检批次/结果/提醒键
            self._conn.executescript(
                """
                    ALTER TABLE versions ADD COLUMN valid_until TEXT;

                    CREATE TABLE IF NOT EXISTS inspection_batches (
                        batch_id        TEXT PRIMARY KEY,
                        inspected_at    TEXT NOT NULL,
                        window_days     INTEGER NOT NULL,
                        expiring_count  INTEGER NOT NULL,
                        expired_count   INTEGER NOT NULL,
                        reminded_count  INTEGER NOT NULL,
                        idempotency_key TEXT
                    );

                    CREATE TABLE IF NOT EXISTS inspection_findings (
                        finding_id     TEXT PRIMARY KEY,
                        batch_id       TEXT NOT NULL
                            REFERENCES inspection_batches(batch_id),
                        category       TEXT NOT NULL,
                        material_id    TEXT NOT NULL,
                        institution_id TEXT NOT NULL,
                        kind           TEXT NOT NULL,
                        title          TEXT NOT NULL,
                        version_id     TEXT NOT NULL,
                        valid_until    TEXT NOT NULL,
                        days_remaining INTEGER,
                        reminder_key   TEXT NOT NULL,
                        reminded       INTEGER NOT NULL,
                        reminded_at    TEXT,
                        created_at     TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_findings_batch
                        ON inspection_findings(batch_id, category);
                    CREATE INDEX IF NOT EXISTS idx_findings_version
                        ON inspection_findings(version_id);

                    CREATE TABLE IF NOT EXISTS inspection_reminders (
                        reminder_key      TEXT PRIMARY KEY,
                        category          TEXT NOT NULL,
                        version_id        TEXT NOT NULL,
                        first_reminded_at TEXT NOT NULL
                    );

                    PRAGMA user_version = 2;
                """
            )

    @contextlib.contextmanager
    def _txn_direct(self) -> Iterator[None]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        # 可重入：同一连接嵌套时复用外层事务
        if self._txn_depth > 0:
            self._txn_depth += 1
            try:
                yield
            finally:
                self._txn_depth -= 1
            return
        self._txn_depth = 1
        try:
            with self._txn_direct():
                yield
        finally:
            self._txn_depth = 0

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------ users
    def upsert_user(self, user: User) -> None:
        self._conn.execute(
            """
            INSERT INTO users(user_id, institution_id, roles_json, display_name)
            VALUES(?,?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET
                institution_id = excluded.institution_id,
                roles_json = excluded.roles_json,
                display_name = excluded.display_name
            """,
            (
                user.user_id,
                user.institution_id,
                json.dumps(list(user.roles), ensure_ascii=False),
                user.display_name,
            ),
        )

    def get_user(self, user_id: str) -> User | None:
        row = self._conn.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        return None if row is None else _row_to_user(row)

    def put_token(self, token: str, user_id: str, at: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO api_tokens(token, user_id, created_at)"
            " VALUES(?,?,?)",
            (token, user_id, at),
        )

    def get_user_by_token(self, token: str) -> User | None:
        if not token:
            return None
        row = self._conn.execute(
            """
            SELECT u.* FROM users u
            JOIN api_tokens t ON t.user_id = u.user_id
            WHERE t.token = ?
            """,
            (token,),
        ).fetchone()
        return None if row is None else _row_to_user(row)

    # ------------------------------------------------------------ idempotency
    def get_idempotent_result(self, key: str) -> dict | None:
        row = self._conn.execute(
            "SELECT result_json FROM idempotency WHERE idempotency_key = ?",
            (key,),
        ).fetchone()
        return None if row is None else json.loads(row["result_json"])

    def save_idempotent_result(self, key: str, result: dict) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO idempotency(idempotency_key, result_json, created_at)"
            " VALUES(?,?,?)",
            (key, json.dumps(result, ensure_ascii=False), ""),
        )

    # ------------------------------------------------------------- materials
    def put_blob(self, blob: Blob) -> None:
        actual = digest_bytes(blob.data)
        if actual != blob.sha256:
            raise ValueError("blob sha256 与内容不一致，拒绝写入")
        self._conn.execute(
            "INSERT OR IGNORE INTO blobs(sha256, data, media_type, size, created_at)"
            " VALUES(?,?,?,?,?)",
            (blob.sha256, blob.data, blob.media_type, len(blob.data), blob.created_at),
        )

    def get_blob(self, sha256: str) -> Blob | None:
        row = self._conn.execute(
            "SELECT * FROM blobs WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if row is None:
            return None
        return Blob(
            sha256=row["sha256"],
            data=bytes(row["data"]),
            media_type=row["media_type"],
            created_at=row["created_at"],
        )

    def iter_blobs(self) -> Iterator[tuple[str, bytes, int]]:
        for row in self._conn.execute("SELECT sha256, data, size FROM blobs"):
            yield row["sha256"], bytes(row["data"]), row["size"]

    def insert_material(self, material: Material) -> None:
        self._conn.execute(
            "INSERT INTO materials(material_id, institution_id, kind, sensitivity,"
            " title, current_version_id, withdrawn, created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (
                material.material_id,
                material.institution_id,
                material.kind,
                material.sensitivity,
                material.title,
                material.current_version_id,
                int(material.withdrawn),
                material.created_at,
            ),
        )

    def get_material(self, material_id: str) -> Material | None:
        row = self._conn.execute(
            "SELECT * FROM materials WHERE material_id = ?", (material_id,)
        ).fetchone()
        return None if row is None else _row_to_material(row)

    def insert_version(self, version: MaterialVersion) -> None:
        self._conn.execute(
            "INSERT INTO versions(version_id, material_id, institution_id, sha256,"
            " size, media_type, version_no, supersedes_version_id, created_by,"
            " created_at, withdrawn, valid_until)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                version.version_id,
                version.material_id,
                version.institution_id,
                version.sha256,
                version.size,
                version.media_type,
                version.version_no,
                version.supersedes_version_id,
                version.created_by,
                version.created_at,
                int(version.withdrawn),
                version.valid_until,
            ),
        )
        self._conn.execute(
            "UPDATE materials SET current_version_id = ? WHERE material_id = ?",
            (version.version_id, version.material_id),
        )

    def get_version(self, version_id: str) -> MaterialVersion | None:
        row = self._conn.execute(
            "SELECT * FROM versions WHERE version_id = ?", (version_id,)
        ).fetchone()
        return None if row is None else _row_to_version(row)

    def find_version_by_digest(
        self, material_id: str, sha256: str
    ) -> MaterialVersion | None:
        row = self._conn.execute(
            "SELECT * FROM versions WHERE material_id = ? AND sha256 = ?"
            " ORDER BY version_no DESC LIMIT 1",
            (material_id, sha256),
        ).fetchone()
        return None if row is None else _row_to_version(row)

    def list_versions(self, material_id: str) -> list[MaterialVersion]:
        rows = self._conn.execute(
            "SELECT * FROM versions WHERE material_id = ? ORDER BY version_no",
            (material_id,),
        ).fetchall()
        return [_row_to_version(r) for r in rows]

    def mark_version_withdrawn(
        self, version_id: str, withdrawn: bool, at: str
    ) -> bool:
        cur = self._conn.execute(
            "UPDATE versions SET withdrawn = ?, withdrawn_at = ? WHERE version_id = ?",
            (int(withdrawn), at if withdrawn else None, version_id),
        )
        return cur.rowcount == 1

    def mark_material_withdrawn(
        self, material_id: str, withdrawn: bool
    ) -> bool:
        cur = self._conn.execute(
            "UPDATE materials SET withdrawn = ? WHERE material_id = ?",
            (int(withdrawn), material_id),
        )
        return cur.rowcount == 1

    def list_validity_candidates(
        self, institution_id: str | None = None
    ) -> list[ValidityCandidate]:
        sql = (
            "SELECT m.material_id AS material_id, m.institution_id AS institution_id,"
            " m.kind AS kind, m.title AS title, v.version_id AS version_id,"
            " v.valid_until AS valid_until"
            " FROM materials m JOIN versions v ON v.version_id = m.current_version_id"
            " WHERE m.withdrawn = 0 AND v.withdrawn = 0 AND v.valid_until IS NOT NULL"
        )
        params: tuple = ()
        if institution_id is not None:
            sql += " AND m.institution_id = ?"
            params = (institution_id,)
        sql += " ORDER BY m.material_id"
        rows = self._conn.execute(sql, params).fetchall()
        return [
            ValidityCandidate(
                material_id=r["material_id"],
                institution_id=r["institution_id"],
                kind=r["kind"],
                title=r["title"],
                version_id=r["version_id"],
                valid_until=r["valid_until"],
            )
            for r in rows
        ]

    # -------------------------------------------------------------- packages
    def insert_package(self, package: ReviewPackage) -> None:
        self._conn.execute(
            "INSERT INTO packages(package_id, institution_id, title, status, created_by,"
            " created_at, sealed_at, manifest_fingerprint, decided_at, decision,"
            " decision_note, review_fingerprint, supersedes_package_id)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                package.package_id,
                package.institution_id,
                package.title,
                package.status,
                package.created_by,
                package.created_at,
                package.sealed_at,
                package.manifest_fingerprint,
                package.decided_at,
                package.decision,
                package.decision_note,
                package.review_fingerprint,
                package.supersedes_package_id,
            ),
        )

    def _row_to_package(self, row: sqlite3.Row, *, with_entries: bool) -> ReviewPackage:
        package = ReviewPackage(
            package_id=row["package_id"],
            institution_id=row["institution_id"],
            title=row["title"],
            status=row["status"],
            created_by=row["created_by"],
            created_at=row["created_at"],
            sealed_at=row["sealed_at"],
            manifest_fingerprint=row["manifest_fingerprint"],
            decided_at=row["decided_at"],
            decision=row["decision"],
            decision_note=row["decision_note"],
            review_fingerprint=row["review_fingerprint"],
            supersedes_package_id=row["supersedes_package_id"],
            entries=[],
        )
        if with_entries:
            package.entries = self._load_entries(package.package_id)
        return package

    def _load_entries(self, package_id: str) -> list[PackageEntry]:
        rows = self._conn.execute(
            "SELECT * FROM entries WHERE package_id = ? ORDER BY material_id, version_id",
            (package_id,),
        ).fetchall()
        return [_row_to_entry(r) for r in rows]

    def get_package(self, package_id: str) -> ReviewPackage | None:
        row = self._conn.execute(
            "SELECT * FROM packages WHERE package_id = ?", (package_id,)
        ).fetchone()
        return None if row is None else self._row_to_package(row, with_entries=True)

    def list_packages(
        self, institution_id: str | None = None,
    ) -> list[ReviewPackage]:
        if institution_id is None:
            rows = self._conn.execute(
                "SELECT * FROM packages ORDER BY created_at"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM packages WHERE institution_id = ? ORDER BY created_at",
                (institution_id,),
            ).fetchall()
        return [self._row_to_package(r, with_entries=True) for r in rows]

    def insert_entry(self, entry: PackageEntry) -> None:
        self._conn.execute(
            "INSERT INTO entries(entry_id, package_id, material_id, version_id,"
            " sha256, kind, sensitivity, added_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (
                entry.entry_id,
                entry.package_id,
                entry.material_id,
                entry.version_id,
                entry.sha256,
                entry.kind,
                entry.sensitivity,
                entry.added_at,
            ),
        )

    def entry_exists(self, package_id: str, version_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM entries WHERE package_id = ? AND version_id = ?",
            (package_id, version_id),
        ).fetchone()
        return row is not None

    def transition_package_status(
        self,
        package_id: str,
        expected_status: str,
        new_status: str,
        **fields,
    ) -> bool:
        allowed = {
            "sealed_at",
            "manifest_fingerprint",
            "decided_at",
            "decision",
            "decision_note",
            "review_fingerprint",
        }
        sets = ["status = ?"]
        params: list = [new_status]
        for key, value in fields.items():
            if key not in allowed:
                raise ValueError(f"不允许通过状态迁移更新字段: {key}")
            sets.append(f"{key} = ?")
            params.append(value)
        params.extend([package_id, expected_status])
        cur = self._conn.execute(
            f"UPDATE packages SET {', '.join(sets)}"
            " WHERE package_id = ? AND status = ?",
            params,
        )
        return cur.rowcount == 1

    # --------------------------------------------------------------- requests
    def insert_request(self, request: ReviewRequest) -> None:
        self._conn.execute(
            "INSERT INTO requests(request_id, package_id, institution_id, reviewer_id,"
            " status, assigned_by, assigned_at, responded_at, completed_at, verdict,"
            " comment, deadline_at_utc, deadline_timezone)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                request.request_id,
                request.package_id,
                request.institution_id,
                request.reviewer_id,
                request.status,
                request.assigned_by,
                request.assigned_at,
                request.responded_at,
                request.completed_at,
                request.verdict,
                request.comment,
                request.deadline_at_utc,
                request.deadline_timezone,
            ),
        )

    def _row_to_request(self, row: sqlite3.Row) -> ReviewRequest:
        return ReviewRequest(
            request_id=row["request_id"],
            package_id=row["package_id"],
            institution_id=row["institution_id"],
            reviewer_id=row["reviewer_id"],
            status=row["status"],
            assigned_by=row["assigned_by"],
            assigned_at=row["assigned_at"],
            responded_at=row["responded_at"],
            completed_at=row["completed_at"],
            verdict=row["verdict"],
            comment=row["comment"],
            deadline_at_utc=row["deadline_at_utc"],
            deadline_timezone=row["deadline_timezone"],
        )

    def get_request(self, request_id: str) -> ReviewRequest | None:
        row = self._conn.execute(
            "SELECT * FROM requests WHERE request_id = ?", (request_id,)
        ).fetchone()
        return None if row is None else self._row_to_request(row)

    def list_requests_by_package(self, package_id: str) -> list[ReviewRequest]:
        rows = self._conn.execute(
            "SELECT * FROM requests WHERE package_id = ? ORDER BY assigned_at",
            (package_id,),
        ).fetchall()
        return [self._row_to_request(r) for r in rows]

    def list_active_requests_by_reviewer(self, reviewer_id: str) -> list[ReviewRequest]:
        rows = self._conn.execute(
            "SELECT * FROM requests WHERE reviewer_id = ? AND status IN"
            " ('pending','accepted','completed') ORDER BY assigned_at",
            (reviewer_id,),
        ).fetchall()
        return [self._row_to_request(r) for r in rows]

    def update_request(self, request: ReviewRequest) -> None:
        self._conn.execute(
            "UPDATE requests SET status = ?, responded_at = ?, completed_at = ?,"
            " verdict = ?, comment = ? WHERE request_id = ?",
            (
                request.status,
                request.responded_at,
                request.completed_at,
                request.verdict,
                request.comment,
                request.request_id,
            ),
        )

    # ------------------------------------------------------------- objections
    def insert_objection(self, objection: Objection) -> None:
        self._conn.execute(
            "INSERT INTO objections(objection_id, request_id, package_id,"
            " institution_id, reviewer_id, category, detail, created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (
                objection.objection_id,
                objection.request_id,
                objection.package_id,
                objection.institution_id,
                objection.reviewer_id,
                objection.category,
                objection.detail,
                objection.created_at,
            ),
        )

    def list_objections_by_package(self, package_id: str) -> list[Objection]:
        rows = self._conn.execute(
            "SELECT * FROM objections WHERE package_id = ? ORDER BY created_at",
            (package_id,),
        ).fetchall()
        return [
            Objection(
                objection_id=r["objection_id"],
                request_id=r["request_id"],
                package_id=r["package_id"],
                institution_id=r["institution_id"],
                reviewer_id=r["reviewer_id"],
                category=r["category"],
                detail=r["detail"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------ audit
    def insert_audit(self, entry: AuditEntry) -> None:
        self._conn.execute(
            "INSERT INTO audit_log(audit_id, package_id, institution_id, actor_id,"
            " action, at, detail_json) VALUES(?,?,?,?,?,?,?)",
            (
                entry.audit_id,
                entry.package_id,
                entry.institution_id,
                entry.actor_id,
                entry.action,
                entry.at,
                json.dumps(entry.detail, ensure_ascii=False),
            ),
        )

    def list_audit(
        self, package_id: str | None = None, limit: int = 200
    ) -> list[AuditEntry]:
        if package_id is None:
            rows = self._conn.execute(
                "SELECT * FROM audit_log ORDER BY at DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM audit_log WHERE package_id = ? ORDER BY at DESC LIMIT ?",
                (package_id, limit),
            ).fetchall()
        return [
            AuditEntry(
                audit_id=r["audit_id"],
                package_id=r["package_id"],
                institution_id=r["institution_id"],
                actor_id=r["actor_id"],
                action=r["action"],
                at=r["at"],
                detail=json.loads(r["detail_json"]),
            )
            for r in rows
        ]

    # ------------------------------------------------------------- 巡检
    def insert_inspection_batch(self, batch: InspectionBatch) -> None:
        self._conn.execute(
            "INSERT INTO inspection_batches(batch_id, inspected_at, window_days,"
            " expiring_count, expired_count, reminded_count, idempotency_key)"
            " VALUES(?,?,?,?,?,?,?)",
            (
                batch.batch_id,
                batch.inspected_at,
                batch.window_days,
                batch.expiring_count,
                batch.expired_count,
                batch.reminded_count,
                batch.idempotency_key,
            ),
        )

    def get_inspection_batch(self, batch_id: str) -> InspectionBatch | None:
        row = self._conn.execute(
            "SELECT * FROM inspection_batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        return None if row is None else _row_to_batch(row)

    def list_inspection_batches(self, limit: int = 50) -> list[InspectionBatch]:
        rows = self._conn.execute(
            "SELECT * FROM inspection_batches ORDER BY inspected_at DESC,"
            " batch_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [_row_to_batch(r) for r in rows]

    def insert_inspection_finding(self, finding: InspectionFinding) -> None:
        self._conn.execute(
            "INSERT INTO inspection_findings(finding_id, batch_id, category,"
            " material_id, institution_id, kind, title, version_id, valid_until,"
            " days_remaining, reminder_key, reminded, reminded_at, created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                finding.finding_id,
                finding.batch_id,
                finding.category,
                finding.material_id,
                finding.institution_id,
                finding.kind,
                finding.title,
                finding.version_id,
                finding.valid_until,
                finding.days_remaining,
                finding.reminder_key,
                int(finding.reminded),
                finding.reminded_at,
                finding.created_at,
            ),
        )

    def list_inspection_findings(
        self, batch_id: str, category: str | None = None
    ) -> list[InspectionFinding]:
        if category is None:
            rows = self._conn.execute(
                "SELECT * FROM inspection_findings WHERE batch_id = ?"
                " ORDER BY category, valid_until, material_id",
                (batch_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM inspection_findings WHERE batch_id = ? AND category = ?"
                " ORDER BY valid_until, material_id",
                (batch_id, category),
            ).fetchall()
        return [_row_to_finding(r) for r in rows]

    def get_reminder(self, reminder_key: str) -> dict | None:
        row = self._conn.execute(
            "SELECT reminder_key, category, version_id, first_reminded_at"
            " FROM inspection_reminders WHERE reminder_key = ?",
            (reminder_key,),
        ).fetchone()
        if row is None:
            return None
        return {
            "key": row["reminder_key"],
            "category": row["category"],
            "version_id": row["version_id"],
            "first_reminded_at": row["first_reminded_at"],
        }

    def insert_reminder_ignore(
        self, key: str, category: str, version_id: str, at: str
    ) -> bool:
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO inspection_reminders(reminder_key, category,"
            " version_id, first_reminded_at) VALUES(?,?,?,?)",
            (key, category, version_id, at),
        )
        return cur.rowcount == 1


def _row_to_user(row: sqlite3.Row) -> User:
    return User(
        user_id=row["user_id"],
        institution_id=row["institution_id"],
        roles=tuple(json.loads(row["roles_json"])),
        display_name=row["display_name"],
    )


def _row_to_material(row: sqlite3.Row) -> Material:
    return Material(
        material_id=row["material_id"],
        institution_id=row["institution_id"],
        kind=row["kind"],
        sensitivity=row["sensitivity"],
        title=row["title"],
        current_version_id=row["current_version_id"],
        withdrawn=bool(row["withdrawn"]),
        created_at=row["created_at"],
    )


def _row_to_version(row: sqlite3.Row) -> MaterialVersion:
    return MaterialVersion(
        version_id=row["version_id"],
        material_id=row["material_id"],
        institution_id=row["institution_id"],
        sha256=row["sha256"],
        size=row["size"],
        media_type=row["media_type"],
        version_no=row["version_no"],
        supersedes_version_id=row["supersedes_version_id"],
        created_by=row["created_by"],
        created_at=row["created_at"],
        withdrawn=bool(row["withdrawn"]),
        valid_until=row["valid_until"],
    )


def _row_to_batch(row: sqlite3.Row) -> InspectionBatch:
    keys = row.keys()
    return InspectionBatch(
        batch_id=row["batch_id"],
        inspected_at=row["inspected_at"],
        window_days=row["window_days"],
        expiring_count=row["expiring_count"],
        expired_count=row["expired_count"],
        reminded_count=row["reminded_count"],
        idempotency_key=row["idempotency_key"] if "idempotency_key" in keys else None,
    )


def _row_to_finding(row: sqlite3.Row) -> InspectionFinding:
    return InspectionFinding(
        finding_id=row["finding_id"],
        batch_id=row["batch_id"],
        category=row["category"],
        material_id=row["material_id"],
        institution_id=row["institution_id"],
        kind=row["kind"],
        title=row["title"],
        version_id=row["version_id"],
        valid_until=row["valid_until"],
        days_remaining=row["days_remaining"],
        reminder_key=row["reminder_key"],
        reminded=bool(row["reminded"]),
        reminded_at=row["reminded_at"],
        created_at=row["created_at"],
    )


def _row_to_entry(row: sqlite3.Row) -> PackageEntry:
    return PackageEntry(
        entry_id=row["entry_id"],
        package_id=row["package_id"],
        material_id=row["material_id"],
        version_id=row["version_id"],
        sha256=row["sha256"],
        kind=row["kind"],
        sensitivity=row["sensitivity"],
        added_at=row["added_at"],
    )
