import json
import logging
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kube-vigil")

app = FastAPI(title="KubeVigil Admission Controller")

LEDGER_PATH = Path(__file__).resolve().parent.parent / "evidence" / "sbom_ledger.json"

def load_sbom_ledger() -> dict:
    if not LEDGER_PATH.exists():
        logger.warning(f"Ledger file not found at {LEDGER_PATH}. Defaulting to empty ledger.")
        return {}
    try:
        with open(LEDGER_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.error(f"Error reading SBOM ledger: {exc}")
        return {}

def verify_image_sbom(image_name: str, ledger: dict) -> tuple[bool, str]:
    if image_name not in ledger:
        return (
            False,
            f"Image '{image_name}' rejected: No verified SBOM or attestation found in ledger."
        )

    entry = ledger[image_name]
    if not entry.get("allowed", False):
        return (
            False,
            f"Image '{image_name}' rejected: Marked as disallowed by supply-chain policy."
        )

    if entry.get("attestation_status") != "VERIFIED":
        return (
            False,
            f"Image '{image_name}' rejected: Attestation status is '{entry.get('attestation_status')}' (expected 'VERIFIED')."
        )

    sbom_format = entry.get("sbom_format", "Unknown")
    return (
        True,
        f"Image '{image_name}' approved: Valid {sbom_format} SBOM recorded."
    )

@app.post("/validate")
async def validate_pod(request: Request):
    review = await request.json()
    req_body = review.get("request", {})
    uid = req_body.get("uid", "")
    pod = req_body.get("object", {})

    containers = pod.get("spec", {}).get("containers", [])
    ledger = load_sbom_ledger()

    for container in containers:
        image = container.get("image", "")
        allowed, reason = verify_image_sbom(image, ledger)
        if not allowed:
            logger.info(f"Admission DENIED for UID={uid}: {reason}")
            return JSONResponse(
                content={
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": uid,
                        "allowed": False,
                        "status": {"code": 403, "message": reason},
                    },
                }
            )

    logger.info(f"Admission ALLOWED for UID={uid}: All container images verified via SBOM ledger.")
    return JSONResponse(
        content={
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": True,
                "status": {"code": 200, "message": "All images verified against SBOM ledger."},
            },
        }
    )
