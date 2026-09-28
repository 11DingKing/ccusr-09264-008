"""HTTP API 端到端：真实启动服务，经 HTTP 走完整流程与鉴权。"""
import base64
import json
import unittest
import urllib.error
import urllib.request

from service_09252_006.api.http_api import HttpApiServer
from service_09252_006.application.container import ApplicationContext
from tests.support import Harness


class ApiClient:
    def __init__(self, base_url: str, token: str | None = None,
                 bootstrap: str | None = None) -> None:
        self.base_url = base_url
        self.token = token
        self.bootstrap = bootstrap

    def request(self, method: str, path: str, body=None,
                idempotency_key=None, raw=False):
        url = self.base_url + path
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if self.bootstrap:
            headers["X-Bootstrap-Token"] = self.bootstrap
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                payload = resp.read()
                if raw:
                    return resp.status, payload, dict(resp.headers)
                return resp.status, json.loads(payload.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            if raw:
                return exc.code, payload, dict(exc.headers)
            try:
                return exc.code, json.loads(payload.decode("utf-8"))
            except json.JSONDecodeError:
                return exc.code, {"raw": payload.decode("utf-8")}


class HttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.server = HttpApiServer(
            self.h.ctx, host="127.0.0.1", port=0, bootstrap_token="boot-secret"
        )
        self.server.start()
        host, port = self.server.address
        self.base = f"http://{host}:{port}"
        self.boot = ApiClient(self.base, bootstrap="boot-secret")

    def tearDown(self) -> None:
        self.server.stop()
        self.h.close()

    def _create_user(self, user_id, roles, institution_id=None, token=None):
        status, body = self.boot.request(
            "POST", "/v1/admin/users",
            {"user_id": user_id, "roles": roles,
             "institution_id": institution_id},
        )
        self.assertEqual(status, 201, body)
        if token:
            status, body = self.boot.request(
                "POST", "/v1/admin/tokens",
                {"user_id": user_id, "token": token},
            )
            self.assertEqual(status, 201, body)
        return ApiClient(self.base, token=token)

    def test_end_to_end_over_http_with_minimal_disclosure(self) -> None:
        admin = self._create_user(
            "admin-a", ["institution_admin"], "inst-a", "tok-admin"
        )
        submitter = self._create_user(
            "sub-a", ["institution_submitter"], "inst-a", "tok-sub"
        )
        authority = self._create_user(
            "auth", ["quality_authority"], None, "tok-auth"
        )
        reviewer = self._create_user(
            "rev-1", ["reviewer"], "inst-ext", "tok-rev"
        )

        # 未认证被拒
        status, body = ApiClient(self.base).request("GET", "/v1/packages")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "permission_denied")

        # 引导端点需要 bootstrap token
        status, body = ApiClient(self.base).request(
            "POST", "/v1/admin/users",
            {"user_id": "x", "roles": [], "institution_id": None},
        )
        self.assertEqual(status, 403)

        # 接收证据
        status, mat = admin.request(
            "POST", "/v1/materials",
            {"kind": "enterprise_feedback", "title": "企业反馈",
             "sensitivity": "sensitive"},
        )
        self.assertEqual(status, 201)
        content = "敏感：企业 X 要求不具名".encode("utf-8")
        status, ver = admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(content).decode("ascii"),
             "media_type": "text/plain"},
            idempotency_key="upload-1",
        )
        self.assertEqual(status, 201)
        # 幂等重放
        status, ver2 = admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(content).decode("ascii")},
            idempotency_key="upload-1",
        )
        self.assertEqual(status, 201)
        self.assertEqual(ver["version_id"], ver2["version_id"])
        self.assertTrue(ver2["replayed"])

        # 组包封存
        status, pkg = admin.request("POST", "/v1/packages", {"title": "2026秋"})
        pid = pkg["package_id"]
        status, _ = admin.request(
            "POST", f"/v1/packages/{pid}/entries",
            {"version_id": ver["version_id"]},
        )
        self.assertEqual(status, 201)
        status, sealed = admin.request("POST", f"/v1/packages/{pid}/seal", {})
        self.assertEqual(status, 200)
        self.assertIn("manifest_fingerprint", sealed)

        # 提交人看不到敏感反馈内容
        status, view = submitter.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(status, 200)
        self.assertTrue(view["entries"][0]["redacted"])
        status, resp = submitter.request(
            "GET", f"/v1/packages/{pid}/entries/{ver['version_id']}/content",
        )
        self.assertEqual(status, 403)

        # 分配评审后可见可下载
        status, req = authority.request(
            "POST", f"/v1/packages/{pid}/assignments",
            {"reviewer_id": "rev-1",
             "deadline_local_iso": "2026-09-25T18:00",
             "deadline_timezone": "Asia/Shanghai"},
        )
        self.assertEqual(status, 201)
        rid = req["request_id"]
        status, _ = reviewer.request(
            "POST", f"/v1/requests/{rid}/respond", {"accept": True}
        )
        self.assertEqual(status, 200)
        status, payload, headers = reviewer.request(
            "GET", f"/v1/packages/{pid}/entries/{ver['version_id']}/content",
            raw=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, content)
        self.assertEqual(headers["X-Content-Sha256"], ver["sha256"])

        # 评审通过并签发
        status, _ = reviewer.request(
            "POST", f"/v1/requests/{rid}/verdict",
            {"verdict": "approve", "comment": "材料齐备"},
        )
        self.assertEqual(status, 200)
        status, decision = authority.request(
            "POST", f"/v1/packages/{pid}/decision",
            {"decision": "approved", "note": "通过"},
            idempotency_key="decide-1",
        )
        self.assertEqual(status, 200)
        status, decision2 = authority.request(
            "POST", f"/v1/packages/{pid}/decision",
            {"decision": "rejected", "note": "重复请求应回放"},
            idempotency_key="decide-1",
        )
        self.assertEqual(status, 200)
        self.assertEqual(decision2["decision"], "approved")
        self.assertTrue(decision2["replayed"])

    def test_health(self) -> None:
        status, body = ApiClient(self.base).request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_inspection_endpoints_and_dedup(self) -> None:
        admin = self._create_user(
            "admin-a", ["institution_admin"], "inst-a", "tok-admin"
        )
        authority = self._create_user(
            "auth", ["quality_authority"], None, "tok-auth"
        )
        submitter = self._create_user(
            "sub-a", ["institution_submitter"], "inst-a", "tok-sub"
        )

        def upload(mid, content, valid_until=None, tz=None):
            body = {"content_base64": base64.b64encode(content).decode("ascii")}
            if valid_until:
                body["valid_until"] = valid_until
            if tz:
                body["valid_until_timezone"] = tz
            return admin.request(
                "POST", f"/v1/materials/{mid}/versions", body
            )

        status, mat1 = admin.request(
            "POST", "/v1/materials",
            {"kind": "syllabus", "title": "即将过期"},
        )
        self.assertEqual(status, 201)
        # 固定时钟 2026-09-25T01:00Z：10 天后到期
        status, v1 = upload(
            mat1["material_id"], b"soon", "2026-10-05T01:00:00+00:00"
        )
        self.assertEqual(status, 201)
        self.assertEqual(v1["valid_until"], "2026-10-05T01:00:00+00:00")

        status, mat2 = admin.request(
            "POST", "/v1/materials",
            {"kind": "syllabus", "title": "已过期"},
        )
        self.assertEqual(status, 201)
        status, _ = upload(
            mat2["material_id"], b"past", "2026-09-20T01:00:00+00:00"
        )
        self.assertEqual(status, 201)

        # 提交人无权巡检
        status, body = submitter.request("POST", "/v1/inspections", {})
        self.assertEqual(status, 403)

        # 首次巡检
        status, first = authority.request(
            "POST", "/v1/inspections", {"window_days": 30}
        )
        self.assertEqual(status, 201)
        self.assertEqual(first["expiring_count"], 1)
        self.assertEqual(first["expired_count"], 1)
        self.assertEqual(first["reminded_count"], 2)
        bid = first["batch_id"]

        # 分别读取两类清单
        status, exp = authority.request(
            "GET", f"/v1/inspections/{bid}/findings?category=expiring"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(exp["findings"]), 1)
        self.assertEqual(exp["findings"][0]["title"], "即将过期")
        status, exd = authority.request(
            "GET", f"/v1/inspections/{bid}/findings?category=expired"
        )
        self.assertEqual(exd["findings"][0]["title"], "已过期")

        # 批次详情与历史列表
        status, detail = authority.request("GET", f"/v1/inspections/{bid}")
        self.assertEqual(status, 200)
        self.assertEqual(len(detail["expiring"]), 1)

        # 重复巡检：新批次但无新提醒
        status, second = authority.request("POST", "/v1/inspections", {})
        self.assertEqual(status, 201)
        self.assertNotEqual(second["batch_id"], bid)
        self.assertEqual(second["reminded_count"], 0)
        self.assertFalse(second["expiring"][0]["reminded"])

        status, listing = authority.request("GET", "/v1/inspections")
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["batches"]), 2)

        # 幂等键重放
        status, r1 = authority.request(
            "POST", "/v1/inspections", {}, idempotency_key="cron-weekly"
        )
        status, r2 = authority.request(
            "POST", "/v1/inspections", {}, idempotency_key="cron-weekly"
        )
        self.assertEqual(r1["batch_id"], r2["batch_id"])
        self.assertTrue(r2["replayed"])


if __name__ == "__main__":
    unittest.main()
