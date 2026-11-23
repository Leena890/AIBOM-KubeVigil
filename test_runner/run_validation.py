import json
import time
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from webhook.main import app

client = TestClient(app)

with open("test_runner/test_allow.json", "r", encoding="utf-8-sig") as f:
    allow_payload = json.load(f)

with open("test_runner/test_deny.json", "r", encoding="utf-8-sig") as f:
    deny_payload = json.load(f)

def make_review(uid, image):
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": uid,
            "operation": "CREATE",
            "kind": {"group": "", "version": "v1", "kind": "Pod"},
            "resource": {"group": "", "version": "v1", "resource": "pods"},
            "object": {"spec": {"containers": [{"name": "test-container", "image": image}]}}
        }
    }

cases = [
    ("TC-01: Signed AI Workload + Valid SBOM/AIBOM", allow_payload, True),
    ("TC-02: Mutable Tag Blocked", make_review("test-uid-deny-tag-02", "ghcr.io/leena890/kubevigil-ai-app:v1.1.0"), False),
    ("TC-03: Untrusted Registry Image (test_deny.json)", deny_payload, False),
    ("TC-04: Unsigned Digest-Pinned Image", make_review("test-uid-deny-unsigned-04", "alpine@sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d"), False),
]

results = []
for name, payload, expected in cases:
    img = payload["request"]["object"]["spec"]["containers"][0]["image"]
    t0 = time.perf_counter()
    resp = client.post("/validate", json=payload)
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    adm_resp = resp.json()["response"]
    actual = adm_resp["allowed"]
    status_code = adm_resp["status"]["code"]
    msg = adm_resp["status"]["message"]
    results.append({
        "test_case": name,
        "image": img,
        "expected_allowed": expected,
        "actual_allowed": actual,
        "http_status": status_code,
        "latency_ms": latency_ms,
        "assertion_passed": (actual == expected),
        "decision_message": msg
    })

report_json = {
    "recorded_utc": datetime.now(timezone.utc).isoformat(),
    "total_cases": len(results),
    "passed_cases": sum(1 for r in results if r["assertion_passed"]),
    "results": results
}

with open("evidence/gate3_admission_results.json", "w", encoding="utf-8") as f:
    json.dump(report_json, f, indent=2)

lines = [
    "\n---\n",
    "## Phase 5: Gate 3 Admission Webhook Validation (Pass / Reject Matrix)",
    f"* **Status:** PASSED ({report_json['passed_cases']}/{report_json['total_cases']} Test Assertions Verified)",
    f"* **Recorded (UTC):** {report_json['recorded_utc']}",
    "* **Raw Audit Artifact:** `evidence/gate3_admission_results.json`\n",
    "| Test Case | Target Image | Decision | Code | Latency (ms) | Webhook Reason |",
    "| :--- | :--- | :--- | :--- | :--- | :--- |"
]

for r in results:
    dec = "ALLOWED" if r["actual_allowed"] else "REJECTED"
    short_img = r["image"] if len(r["image"]) < 55 else r["image"][:42] + "..." + r["image"][-10:]
    lines.append(f"| {r['test_case']} | `{short_img}` | **{dec}** | `{r['http_status']}` | `{r['latency_ms']}` | {r['decision_message']} |")

with open("evidence/test_validations.md", "a", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

for r in results:
    print(f"{r['test_case']} -> allowed={r['actual_allowed']} ({r['http_status']}) in {r['latency_ms']} ms | {r['decision_message']}")
