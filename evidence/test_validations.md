# KubeVigil Implementation & Validation Report

**Project:** KubeVigil — Cryptographic Admission Control & Provenance Verification for Containerized AI Workloads
**Target Environment:** Kubernetes (Local & AWS EKS)

---

## Phase 1: AI Application Containerization & Immutable Digest Pinning
- **Status:** COMPLETED
- **Application Components:** Python FastAPI inference server (`app.py`), 10,000-sample anomaly detection training pipeline (`train.py`), exported ONNX model (`model.onnx`), and AIBOM metadata (`model_metadata.json`).
- **Container Registry:** GitHub Container Registry (`ghcr.io`)
- **Tagged Image Reference:** `ghcr.io/leena890/kubevigil-ai-app:v1.1.0`
- **Immutable SHA-256 Digest:** `ghcr.io/leena890/kubevigil-ai-app@sha256:0be7b7f8d430a21b807b590b7f81785b01421979001ef9be70449bc9326d1130`
- **Security Rationale:** Pinning by SHA-256 digest eliminates mutable tag-substitution attacks and binds the container layers and ONNX model artifacts to a single immutable cryptographic hash.

---

## Phase 2: Keyless Cryptographic Signing (Sigstore Fulcio + Rekor)
- **Status:** COMPLETED
- **Signing Tool:** Sigstore Cosign (`v3.1.4`)
- **Authentication Flow:** Keyless OIDC device authentication via GitHub (`https://github.com/login/oauth`)
- **Cryptographic Execution:**
  1. Generated an ephemeral ECDSA-P256 keypair in memory.
  2. Obtained a short-lived X.509 code-signing certificate from the Sigstore Fulcio Certificate Authority bound to the authenticated GitHub identity.
  3. Signed the immutable image digest (`sha256:0be7b7f8d430a21b807b590b7f81785b01421979001ef9be70449bc9326d1130`), recorded the signature proof in the public Rekor transparency log, attached the Sigstore bundle to `ghcr.io`, and discarded the ephemeral private key.

---

## Phase 3: Gate 2 Policy Verification (Strict Identity & Issuer Pinning)
- **Status:** PASSED
- **Verification Command Executed:**
  ```powershell
  cosign verify --certificate-identity="leenaks1998@gmail.com" --certificate-oidc-issuer="[https://github.com/login/oauth](https://github.com/login/oauth)" ghcr.io/leena890/kubevigil-ai-app@sha256:0be7b7f8d430a21b807b590b7f81785b01421979001ef9be70449bc9326d1130
  ```

---

## Phase 4: Gate 1 SBOM & AIBOM Provenance Validation
- **Status:** PASSED
- **Container Image Digest:** `ghcr.io/leena890/kubevigil-ai-app@sha256:0be7b7f8d430a21b807b590b7f81785b01421979001ef9be70449bc9326d1130`
- **Software Bill of Materials (SBOM):**
  - **Tool & Format:** Anchore Syft (`v1.57.2`) — CycloneDX JSON (`evidence/kubevigil-ai-app.sbom.json`)
  - **Cataloged Inventory:** 120 software packages, 777 executables, 495 file digests
  - **SBOM File SHA-256:** `781ffa39b5bb9bf6d5b10292d110f9c9184cdf38da80141f36b41bf584ec233c`
- **Artificial Intelligence Bill of Materials (AIBOM):**
  - **Model Name & Version:** `kubevigil-container-anomaly-detector` (`v1.1.0`)
  - **Algorithm & Framework:** `RandomForestClassifier(n_estimators=100, max_depth=8)` / `scikit-learn-onnx` (`Apache-2.0`)
  - **Dataset Size & SHA-256:** `10000` samples (`438f7ce3550eeee7632060b7bc7654e7ac50136f7099c270622ddd79f3a2ff11`)
  - **ONNX Model Artifact SHA-256:** `c8d3571811fed7390a57130418bdb8c549d67c1b310a374055ded529de78c83e`
  - **Evaluation Metrics:** Accuracy = `0.963`, Precision = `0.9696`, Recall = `0.956`, F1 = `0.9627`, 5-Fold CV F1 = `0.9694`, ROC-AUC = `0.9951`
- **Ledger Binding:** Registered under `evidence/sbom_ledger.json` with `attestation_status: VERIFIED` and `allowed: true`.

---

## Phase 5: Gate 3 Admission Webhook Validation (Pass / Reject Matrix)
- **Status:** PASSED (4/4 Test Assertions Verified)
- **Recorded (UTC):** 2026-11-23T09:21:18.426817+00:00
- **Raw Audit Artifact:** `evidence/gate3_admission_results.json`

| Test Case | Target Image | Decision | Code | Latency (ms) | Webhook Reason |
| :--- | :--- | :--- | :--- | :--- | :--- |
| TC-01: Signed AI Workload + Valid SBOM/AIBOM | `ghcr.io/leena890/kubevigil-ai-app@sha256:0...c9326d1130` | **ALLOWED** | `200` | `6367.93` | All images cryptographically signed and SBOM-verified. |
| TC-02: Mutable Tag Blocked | `ghcr.io/leena890/kubevigil-ai-app:v1.1.0` | **REJECTED** | `403` | `16.16` | Image 'ghcr.io/leena890/kubevigil-ai-app:v1.1.0' rejected: Mutable tags disallowed. Image must be pinned to an immutable '@sha256:<digest>'. |
| TC-03: Untrusted Registry Image (test_deny.json) | `untrusted-registry.io/app:latest` | **REJECTED** | `403` | `14.96` | Image 'untrusted-registry.io/app:latest' rejected: Mutable tags disallowed. Image must be pinned to an immutable '@sha256:<digest>'. |
| TC-04: Unsigned Digest-Pinned Image | `alpine@sha256:beefdbd8a1da6d2915566fde36db...d16dc0d06d` | **REJECTED** | `403` | `2906.41` | Digest identity 'alpine@sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d' rejected: Cosign signature verification failed (error during command execution: no signatures found). |

---

## Phase 6: Live Kubernetes Cluster Enforcement & 3-Scenario Supervisor Demo
- **Status:** PASSED
- **Cluster Context:** `docker-desktop`
- **Admission Webhook Deployment:** `kubevigil-webhook` (`kubevigil:v11`, Cosign `v3.0.2`)
- **Live Cluster Enforcement Audit Logs:**
  1. **Scenario 1 — Mutable Tag Attack (`UID=4f151099-1d74-4136-a71c-6588931fd6e2`):** `ghcr.io/leena890/kubevigil-ai-app:v1.1.0` rejected immediately (`Mutable tags disallowed`).
  2. **Scenario 2 — Unsigned Digest Attack (`UID=5db52ea6-d2fd-4ab6-aaa2-ac3aaee51323`):** `alpine@sha256:beefdbd8...` rejected via Cosign (`no signatures found`).
  3. **Scenario 3 — Signed & SBOM/AIBOM-Verified AI Workload (`UID=5ee36e1e-f7f4-4efc-bb8a-96634ad8fa86`):** `ghcr.io/leena890/kubevigil-ai-app@sha256:0be7b7f8d430a21b807b590b7f81785b01421979001ef9be70449bc9326d1130` admitted and reached `Running (1/1 Ready)`.
- **Runtime ONNX Inference & AIBOM Verification (`kubevigil-ai-app`):**
  - `GET /aibom` -> Verified `v1.1.0` `RandomForestClassifier` (`10,000` samples, `eval_accuracy=0.963`, `eval_f1=0.9627`, `eval_roc_auc=0.9951`)
  - `POST /predict` (Normal Telemetry) -> `{"prediction":"BENIGN","label":0}`
  - `POST /predict` (Anomalous Telemetry) -> `{"prediction":"MALICIOUS_ANOMALY","label":1}`
