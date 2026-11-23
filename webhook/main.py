import json
import logging
import os
import shutil
import subprocess
from typing import Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

try:
    from webhook.schemas import AdmissionResponse, AdmissionRequest, AdmissionReview
except ModuleNotFoundError:
    from schemas import AdmissionResponse, AdmissionRequest, AdmissionReview

try:
    from webhook.sbom_verifier import verify_sbom_compliance
except ModuleNotFoundError:
    from sbom_verifier import verify_sbom_compliance

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("kube-vigil")

app = FastAPI(title="KubeVigil Admission Webhook", version="0.6.0")

# Trusted Sigstore signer policy (configurable via environment variables)
TRUSTED_IDENTITY = os.getenv("COSIGN_IDENTITY", "leenaks1998@gmail.com")
TRUSTED_ISSUER = os.getenv("COSIGN_OIDC_ISSUER", "https://github.com/login/oauth")


def verify_image_signature(image_str: str) -> Tuple[bool, str]:
    """
    Validate container image cryptographically via Sigstore Cosign.
    Requires an immutable @sha256 digest and a valid signature from the trusted identity.
    """
    # 1. Enforce immutable @sha256 digest
    if "@sha256:" not in image_str:
        return (
            False,
            f"Image '{image_str}' rejected: Mutable tags disallowed. "
            f"Image must be pinned to an immutable '@sha256:<digest>'."
        )

    # 2. Execute live Cosign verification against registry + Sigstore Rekor/Fulcio
    cmd = [
        (shutil.which('cosign') or r'C:\Users\leena\AppData\Local\Microsoft\WinGet\Packages\Sigstore.Cosign_Microsoft.Winget.Source_8wekyb3d8bbwe\cosign-windows-amd64.exe'),
        "verify",
        f"--certificate-identity={TRUSTED_IDENTITY}",
        f"--certificate-oidc-issuer={TRUSTED_ISSUER}",
        image_str,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15
        )
    except subprocess.TimeoutExpired:
        logger.error(f"Cosign verification timed out for {image_str}")
        return (
            False,
            f"Digest identity '{image_str}' rejected: Cryptographic verification timed out."
        )
    except Exception as e:
        logger.error(f"Cosign execution error for {image_str}: {e}")
        return (
            False,
            f"Digest identity '{image_str}' rejected: Verification engine error."
        )

    if result.returncode != 0:
        err_detail = (result.stderr or "").strip().splitlines()[-1] if result.stderr else "No valid signature found."
        return (
            False,
            f"Digest identity '{image_str}' rejected: Cosign signature verification failed ({err_detail})."
        )

    return (
        True,
        f"Cryptographic signature verified via Sigstore for identity '{TRUSTED_IDENTITY}'."
    )


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/validate")
async def validate_admission(request: Request):
    raw_body = await request.body()
    try:
        data = json.loads(raw_body)
        admission_review = AdmissionReview(**data)
    except Exception as e:
        logger.error(f"Failed to parse admission review request: {e}")
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid admission review request structure."}
        )

    req = admission_review.request
    uid = req.uid
    logger.info(f"Evaluating AdmissionReview UID={uid} for Resource={req.resource}")

    pod_obj = req.object
    containers = []
    if pod_obj and pod_obj.spec:
        containers = list(pod_obj.spec.containers or []) + list(pod_obj.spec.initContainers or [])

    for c in containers:
        image_str = c.image

        # Gate 1 & 2: Immutable @sha256 digest + Cosign signature verification
        allowed, reason = verify_image_signature(image_str)
        if not allowed:
            logger.info(f"Admission DENIED for UID={uid}: {reason}")
            return AdmissionReview(
                apiVersion=admission_review.apiVersion,
                kind=admission_review.kind,
                response=AdmissionResponse(
                    uid=uid,
                    allowed=False,
                    status={"code": 403, "message": reason}
                )
            )

        # Gate 3: SBOM ledger and SHA-256 artifact compliance verification
        sbom_allowed, sbom_reason = verify_sbom_compliance(image_str)
        if not sbom_allowed:
            logger.info(f"Admission DENIED for UID={uid}: {sbom_reason}")
            return AdmissionReview(
                apiVersion=admission_review.apiVersion,
                kind=admission_review.kind,
                response=AdmissionResponse(
                    uid=uid,
                    allowed=False,
                    status={"code": 403, "message": sbom_reason}
                )
            )

    logger.info(f"Admission ALLOWED for UID={uid}: All container digests verified via Cosign and SBOM ledger.")
    return AdmissionReview(
        apiVersion=admission_review.apiVersion,
        kind=admission_review.kind,
        response=AdmissionResponse(
            uid=uid,
            allowed=True,
            status={"code": 200, "message": "All images cryptographically signed and SBOM-verified."}
        )
    )



