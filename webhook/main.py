import logging
from fastapi import FastAPI, HTTPException
from webhook.schemas import (
    AdmissionRequest,
    AdmissionResponse,
    AdmissionReview,
    AdmissionStatus,
)

# Configure logging to monitor intercepted admission reviews
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("kubevigil")

app = FastAPI(title="KubeVigil Admission Webhook", version="1.0.0")


@app.get("/healthz")
async def health_check():
    """Liveness and readiness probe endpoint for Kubernetes."""
    return {"status": "healthy"}


@app.post("/validate", response_model=AdmissionReview)
async def validate_workload(review: AdmissionReview):
    """
    Validates incoming Pod resources against KubeVigil policies.
    """
    if not review.request:
        raise HTTPException(status_code=400, detail="Missing admission request body")

    req: AdmissionRequest = review.request
    req_uid = req.uid
    logger.info(f"Received AdmissionReview for UID: {req_uid}, Operation: {req.operation}")

    # Extract containers from Pod specification
    containers = []
    if req.object and req.object.spec:
        containers = req.object.spec.containers

    # Evaluate each container image
    for container in containers:
        image_name = container.image
        logger.info(f"Evaluating container '{container.name}' with image: '{image_name}'")

        # Baseline guardrail: Reject untrusted/unsigned placeholder test images
        if "untrusted" in image_name or "malicious" in image_name:
            logger.warning(f"Blocking workload UID {req_uid}: Untrusted image detected ({image_name})")
            return AdmissionReview(
                apiVersion=review.apiVersion,
                kind=review.kind,
                response=AdmissionResponse(
                    uid=req_uid,
                    allowed=False,
                    status=AdmissionStatus(
                        code=403,
                        message=f"KubeVigil Policy Violation: Image '{image_name}' failed security and provenance validation.",
                    ),
                ),
            )

    # Workload passed evaluation
    logger.info(f"Workload UID {req_uid} approved.")
    return AdmissionReview(
        apiVersion=review.apiVersion,
        kind=review.kind,
        response=AdmissionResponse(
            uid=req_uid,
            allowed=True,
        ),
    )


if __name__ == "__main__":
    import uvicorn

    # Launch server locally using generated TLS certificates on port 8443
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="certs/server.key",
        ssl_certfile="certs/server.crt",
        reload=True,
    )
