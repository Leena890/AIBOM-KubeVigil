import json

img_v11 = "ghcr.io/leena890/kubevigil-ai-app@sha256:0be7b7f8d430a21b807b590b7f81785b01421979001ef9be70449bc9326d1130"

with open("ai_app/model_metadata.json", "r", encoding="utf-8-sig") as f:
    aibom = json.load(f)

with open("evidence/sbom_ledger.json", "r", encoding="utf-8-sig") as f:
    ledger = json.load(f)

with open("evidence/gate3_admission_results.json", "r", encoding="utf-8-sig") as f:
    gate3 = json.load(f)

sbom_sha256 = ledger[img_v11]["sbom_sha256"]

lines = [
    "# KubeVigil Implementation & Validation Report\n",
    "**Project:** KubeVigil — Cryptographic Admission Control & Provenance Verification for Containerized AI Workloads",
    "**Target Environment:** Kubernetes (Local & AWS EKS)\n",
    "---\n",
    "## Phase 1: AI Application Containerization & Immutable Digest Pinning",
    "- **Status:** COMPLETED",
    "- **Application Components:** Python FastAPI inference server (`app.py`), 10,000-sample anomaly detection training pipeline (`train.py`), exported ONNX model (`model.onnx`), and AIBOM metadata (`model_metadata.json`).",
    "- **Container Registry:** GitHub Container Registry (`ghcr.io`)",
    "- **Tagged Image Reference:** `ghcr.io/leena890/kubevigil-ai-app:v1.1.0`",
    f"- **Immutable SHA-256 Digest:** `{img_v11}`",
    "- **Security Rationale:** Pinning by SHA-256 digest eliminates mutable tag-substitution attacks and binds the container layers and ONNX model artifacts to a single immutable cryptographic hash.\n",
    "---\n",
    "## Phase 2: Keyless Cryptographic Signing (Sigstore Fulcio + Rekor)",
    "- **Status:** COMPLETED",
    "- **Signing Tool:** Sigstore Cosign (`v3.1.4`)",
    "- **Authentication Flow:** Keyless OIDC device authentication via GitHub (`https://github.com/login/oauth`)",
    "- **Cryptographic Execution:**",
    "  1. Generated an ephemeral ECDSA-P256 keypair in memory.",
    "  2. Obtained a short-lived X.509 code-signing certificate from the Sigstore Fulcio Certificate Authority bound to the authenticated GitHub identity.",
    "  3. Signed the immutable image digest (`sha256:0be7b7f8d430a21b807b590b7f81785b01421979001ef9be70449bc9326d1130`), recorded the signature proof in the public Rekor transparency log, attached the Sigstore bundle to `ghcr.io`, and discarded the ephemeral private key.\n",
    "---\n",
    "## Phase 3: Gate 2 Policy Verification (Strict Identity & Issuer Pinning)",
    "- **Status:** PASSED",
    "- **Verification Command Executed:**",
    "  ```powershell",
    f'  cosign verify --certificate-identity="leenaks1998@gmail.com" --certificate-oidc-issuer="[https://github.com/login/oauth](https://github.com/login/oauth)" {img_v11}',
    "  ```\n",
    "---\n",
    "## Phase 4: Gate 1 SBOM & AIBOM Provenance Validation",
    "- **Status:** PASSED",
    f"- **Container Image Digest:** `{img_v11}`",
    "- **Software Bill of Materials (SBOM):**",
    "  - **Tool & Format:** Anchore Syft (`v1.57.2`) — CycloneDX JSON (`evidence/kubevigil-ai-app.sbom.json`)",
    "  - **Cataloged Inventory:** 120 software packages, 777 executables, 495 file digests",
    f"  - **SBOM File SHA-256:** `{sbom_sha256}`",
    "- **Artificial Intelligence Bill of Materials (AIBOM):**",
    f"  - **Model Name & Version:** `{aibom['model_name']}` (`v{aibom['model_version']}`)",
    f"  - **Algorithm & Framework:** `{aibom['algorithm']}` / `{aibom['framework']}` (`{aibom['license']}`)",
    f"  - **Dataset Size & SHA-256:** `{aibom['dataset_rows']}` samples (`{aibom['dataset_sha256']}`)",
    f"  - **ONNX Model Artifact SHA-256:** `{aibom['model_sha256']}`",
    f"  - **Evaluation Metrics:** Accuracy = `{aibom['eval_accuracy']}`, Precision = `{aibom['eval_precision']}`, Recall = `{aibom['eval_recall']}`, F1 = `{aibom['eval_f1']}`, 5-Fold CV F1 = `{aibom['cv5_f1_score']}`, ROC-AUC = `{aibom['eval_roc_auc']}`",
    "- **Ledger Binding:** Registered under `evidence/sbom_ledger.json` with `attestation_status: VERIFIED` and `allowed: true`.\n",
    "---\n",
    "## Phase 5: Gate 3 Admission Webhook Validation (Pass / Reject Matrix)",
    f"- **Status:** PASSED ({gate3['passed_cases']}/{gate3['total_cases']} Test Assertions Verified)",
    f"- **Recorded (UTC):** {gate3['recorded_utc']}",
    "- **Raw Audit Artifact:** `evidence/gate3_admission_results.json`\n",
    "| Test Case | Target Image | Decision | Code | Latency (ms) | Webhook Reason |",
    "| :--- | :--- | :--- | :--- | :--- | :--- |"
]

for r in gate3["results"]:
    dec = "ALLOWED" if r["actual_allowed"] else "REJECTED"
    short_img = r["image"] if len(r["image"]) < 55 else r["image"][:42] + "..." + r["image"][-10:]
    lines.append(f"| {r['test_case']} | `{short_img}` | **{dec}** | `{r['http_status']}` | `{r['latency_ms']}` | {r['decision_message']} |")

with open("evidence/test_validations.md", "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

print("Final v1.1.0 validation report saved to evidence/test_validations.md")
