import hashlib
import json
import os
from pathlib import Path
from typing import Tuple

DEFAULT_LEDGER_PATH = os.getenv("SBOM_LEDGER_PATH", "/evidence/sbom_ledger.json")


def _compute_sha256(file_path: Path) -> str:
    sha256 = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest().lower()


def verify_sbom_compliance(image_str: str, ledger_path: str = DEFAULT_LEDGER_PATH) -> Tuple[bool, str]:
    """
    Verify that a signed container image digest has a valid, untampered SBOM
    record approved in the KubeVigil SBOM ledger.
    """
    path = Path(ledger_path)
    if not path.exists():
        local_fallback = Path("evidence/sbom_ledger.json")
        if local_fallback.exists():
            path = local_fallback
        else:
            return False, f"SBOM verification failed: Ledger file not found at '{ledger_path}'."

    try:
        ledger = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        return False, f"SBOM verification failed: Unable to parse SBOM ledger ({e})."

    record = ledger.get(image_str)
    if not record:
        return (
            False,
            f"Digest identity '{image_str}' rejected: No approved SBOM record found in ledger."
        )

    if not record.get("allowed", False):
        return (
            False,
            f"Digest identity '{image_str}' rejected: SBOM policy marks image as disallowed."
        )

    if record.get("attestation_status") != "VERIFIED":
        return (
            False,
            f"Digest identity '{image_str}' rejected: SBOM attestation status is "
            f"'{record.get('attestation_status')}', expected 'VERIFIED'."
        )

    expected_sha256 = (record.get("sbom_sha256") or "").lower()
    if not expected_sha256:
        return (
            False,
            f"Digest identity '{image_str}' rejected: Missing 'sbom_sha256' in ledger record."
        )

    sbom_file = record.get("sbom_file")
    if sbom_file:
        sbom_path = Path(sbom_file)
        if not sbom_path.exists():
            alt_path = Path(sbom_file.lstrip("/"))
            if alt_path.exists():
                sbom_path = alt_path

        if not sbom_path.exists():
            return (
                False,
                f"Digest identity '{image_str}' rejected: Referenced SBOM artifact '{sbom_file}' missing."
            )

        actual_sha256 = _compute_sha256(sbom_path)
        if actual_sha256 != expected_sha256:
            return (
                False,
                f"Digest identity '{image_str}' rejected: SBOM SHA-256 mismatch "
                f"(expected {expected_sha256}, got {actual_sha256})."
            )

    sbom_format = record.get("sbom_format", "Unknown")
    return (
        True,
        f"SBOM verified ({sbom_format}, sha256={expected_sha256[:12]}...)."
    )
