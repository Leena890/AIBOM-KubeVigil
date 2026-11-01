from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AdmissionStatus(BaseModel):
    message: Optional[str] = None
    code: Optional[int] = None


class AdmissionResponse(BaseModel):
    uid: str
    allowed: bool
    status: Optional[AdmissionStatus] = None


class Container(BaseModel):
    name: str
    image: str


class PodSpec(BaseModel):
    containers: List[Container] = []
    initContainers: Optional[List[Container]] = []


class PodObject(BaseModel):
    metadata: Optional[Dict[str, Any]] = None
    spec: Optional[PodSpec] = None


class AdmissionRequest(BaseModel):
    uid: str
    kind: Dict[str, str]
    resource: Dict[str, str]
    operation: str
    object: Optional[PodObject] = None


class AdmissionReview(BaseModel):
    apiVersion: str = "admission.k8s.io/v1"
    kind: str = "AdmissionReview"
    request: Optional[AdmissionRequest] = None
    response: Optional[AdmissionResponse] = None