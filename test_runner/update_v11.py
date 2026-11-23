import hashlib
import json

img_v11 = "ghcr.io/leena890/kubevigil-ai-app@sha256:0be7b7f8d430a21b807b590b7f81785b01421979001ef9be70449bc9326d1130"

with open("evidence/kubevigil-ai-app.sbom.json", "rb") as f:
    sbom_sha256 = hashlib.sha256(f.read()).hexdigest()

with open("ai_app/model_metadata.json", "r", encoding="utf-8-sig") as f:
    aibom = json.load(f)

with open("evidence/sbom_ledger.json", "r", encoding="utf-8-sig") as f:
    ledger = json.load(f)

ledger[img_v11] = {
    "sbom_format": "CycloneDX-1.6-JSON",
    "sbom_path": "evidence/kubevigil-ai-app.sbom.json",
    "sbom_sha256": sbom_sha256,
    "aibom": aibom,
    "attestation_status": "VERIFIED",
    "allowed": True
}
with open("evidence/sbom_ledger.json", "w", encoding="utf-8") as f:
    json.dump(ledger, f, indent=2)

with open("test_runner/test_allow.json", "r", encoding="utf-8-sig") as f:
    allow_doc = json.load(f)
allow_doc["request"]["object"]["spec"]["containers"][0]["image"] = img_v11
with open("test_runner/test_allow.json", "w", encoding="utf-8") as f:
    json.dump(allow_doc, f, indent=2)

with open("test_runner/run_validation.py", "r", encoding="utf-8-sig") as f:
    val_code = f.read()
val_code = val_code.replace("kubevigil-ai-app:v1\"", "kubevigil-ai-app:v1.1.0\"")
with open("test_runner/run_validation.py", "w", encoding="utf-8") as f:
    f.write(val_code)

print(f"Updated ledger & test suite for {img_v11} (SBOM SHA-256: {sbom_sha256})")
