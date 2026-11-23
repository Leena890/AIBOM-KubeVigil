import hashlib
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# 1. Generate realistic, overlapping Kubernetes container telemetry (10,000 samples)
# Features: [syscall_rate, outbound_conns, cpu_pct, is_root]
rng = np.random.default_rng(42)

# Benign Class (0) - 5,000 samples across 3 realistic workload profiles
# A. Standard microservices (3,500)
b_std = np.column_stack([
    np.clip(rng.normal(220, 95, 3500), 10, None),
    np.clip(rng.normal(6, 4, 3500), 0, None),
    np.clip(rng.normal(24, 12, 3500), 1, 100),
    rng.binomial(1, 0.08, 3500)
])
# B. Bursty batch/ETL pods (900) - high CPU & syscalls, legitimate traffic
b_burst = np.column_stack([
    np.clip(rng.normal(1450, 450, 900), 200, None),
    np.clip(rng.normal(14, 7, 900), 1, None),
    np.clip(rng.normal(68, 16, 900), 20, 100),
    rng.binomial(1, 0.15, 900)
])
# C. Legacy / system sidecars running as root (600)
b_root = np.column_stack([
    np.clip(rng.normal(480, 180, 600), 50, None),
    np.clip(rng.normal(10, 5, 600), 0, None),
    np.clip(rng.normal(32, 14, 600), 2, 100),
    np.ones(600)
])

# Malicious Class (1) - 5,000 samples across 3 attack profiles
# A. Cryptominer / resource-hijacking container (2,200)
m_miner = np.column_stack([
    np.clip(rng.normal(2600, 750, 2200), 400, None),
    np.clip(rng.normal(28, 12, 2200), 2, None),
    np.clip(rng.normal(84, 11, 2200), 45, 100),
    rng.binomial(1, 0.65, 2200)
])
# B. Low-and-slow C2 reverse shell / data exfiltration (1,800) - overlaps benign CPU/syscalls
m_c2 = np.column_stack([
    np.clip(rng.normal(780, 320, 1800), 120, None),
    np.clip(rng.normal(42, 15, 1800), 10, None),
    np.clip(rng.normal(36, 15, 1800), 5, 95),
    rng.binomial(1, 0.55, 1800)
])
# C. Privilege escalation & container breakout burst (1,000)
m_esc = np.column_stack([
    np.clip(rng.normal(3400, 900, 1000), 800, None),
    np.clip(rng.normal(55, 20, 1000), 8, None),
    np.clip(rng.normal(72, 18, 1000), 25, 100),
    rng.binomial(1, 0.85, 1000)
])

X = np.vstack([b_std, b_burst, b_root, m_miner, m_c2, m_esc]).astype(np.float32)
y = np.array([0] * 5000 + [1] * 5000, dtype=np.int64)

# Shuffle deterministically
perm = rng.permutation(len(y))
X, y = X[perm], y[perm]

dataset_sha256 = hashlib.sha256(X.tobytes() + y.tobytes()).hexdigest()

# 2. Stratified 80/20 split + 5-fold cross-validation
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

clf = RandomForestClassifier(
    n_estimators=100,
    max_depth=8,
    min_samples_leaf=5,
    random_state=42,
    n_jobs=-1
)

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_f1 = float(np.mean(cross_val_score(clf, X_train, y_train, cv=cv, scoring="f1")))

clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]

acc = float(accuracy_score(y_test, y_pred))
prec = float(precision_score(y_test, y_pred))
rec = float(recall_score(y_test, y_pred))
f1 = float(f1_score(y_test, y_pred))
auc = float(roc_auc_score(y_test, y_prob))

# 3. Export to ONNX format
initial_type = [("float_input", FloatTensorType([None, 4]))]
onnx_model = convert_sklearn(clf, initial_types=initial_type, target_opset=15)
with open("ai_app/model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

with open("ai_app/model.onnx", "rb") as f:
    model_sha256 = hashlib.sha256(f.read()).hexdigest()

metadata = {
    "model_name": "kubevigil-container-anomaly-detector",
    "model_version": "1.1.0",
    "framework": "scikit-learn-onnx",
    "algorithm": "RandomForestClassifier(n_estimators=100, max_depth=8)",
    "license": "Apache-2.0",
    "dataset_rows": int(len(y)),
    "features": ["syscall_rate", "outbound_conns", "cpu_pct", "is_root"],
    "dataset_sha256": dataset_sha256,
    "model_sha256": model_sha256,
    "cv5_f1_score": round(cv_f1, 4),
    "eval_accuracy": round(acc, 4),
    "eval_precision": round(prec, 4),
    "eval_recall": round(rec, 4),
    "eval_f1": round(f1, 4),
    "eval_roc_auc": round(auc, 4)
}
with open("ai_app/model_metadata.json", "w", encoding="utf-8") as f:
    json.dump(metadata, f, indent=2)

print(json.dumps(metadata, indent=2))
