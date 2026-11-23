import json
import os
import numpy as np
import onnxruntime as rt
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="KubeVigil Container Anomaly Detector", version="1.0.0")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.onnx")
META_PATH = os.path.join(BASE_DIR, "model_metadata.json")

session = rt.InferenceSession(MODEL_PATH, providers=["CPUExecutionProvider"])
input_name = session.get_inputs()[0].name
label_name = session.get_outputs()[0].name

with open(META_PATH, "r", encoding="utf-8") as f:
    MODEL_METADATA = json.load(f)


class TelemetryInput(BaseModel):
    syscall_rate: float = 150.0
    outbound_conns: float = 4.0
    cpu_pct: float = 20.0
    is_root: int = 0


@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL_METADATA["model_name"]}


@app.get("/aibom")
def get_aibom():
    return MODEL_METADATA


@app.post("/predict")
def predict(data: TelemetryInput):
    features = np.array(
        [[data.syscall_rate, data.outbound_conns, data.cpu_pct, float(data.is_root)]],
        dtype=np.float32,
    )
    pred = int(session.run([label_name], {input_name: features})[0][0])
    verdict = "MALICIOUS_ANOMALY" if pred == 1 else "BENIGN"
    return {"prediction": verdict, "label": pred}
