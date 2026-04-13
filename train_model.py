"""
Phase 3 - Lightweight ML Training
Phishing Detection System

Trains and compares lightweight classifiers:
- Logistic Regression
- Decision Tree
- Random Forest

Exports:
- Individual models as joblib
- Best model as joblib
- Metrics as JSON
- Optional ONNX export for the best model (if skl2onnx is installed)
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier


def _resolve_data_path() -> Path:
    candidates = [Path("data/phishing.csv"), Path("phishing.csv")]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError("Could not find dataset. Expected data/phishing.csv or phishing.csv")


def _load_xy(csv_path: Path) -> tuple[pd.DataFrame, np.ndarray, str]:
    df = pd.read_csv(csv_path)

    target_candidates = ["Result", "class", "Class", "label", "Label"]
    target_col = next((c for c in target_candidates if c in df.columns), None)
    if target_col is None:
        raise ValueError(f"Target column not found. Expected one of {target_candidates}")

    # Remove common index-like columns if present.
    drop_cols = {"Index", "index", "Unnamed: 0"}
    feature_cols = [c for c in df.columns if c != target_col and c not in drop_cols]

    X = df[feature_cols].copy()
    y_raw = df[target_col].astype(int).to_numpy()

    # Normalize labels for binary classification: phishing=-1 -> 0, legit=1 -> 1.
    y = np.where(y_raw == -1, 0, 1).astype(np.int64)
    return X, y, target_col


def _build_models(random_state: int = 42) -> dict[str, object]:
    return {
        "logistic_regression": LogisticRegression(max_iter=1000, solver="liblinear", random_state=random_state),
        "decision_tree": DecisionTreeClassifier(max_depth=8, random_state=random_state),
        "random_forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            min_samples_split=4,
            random_state=random_state,
            n_jobs=-1,
        ),
    }


def _evaluate(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }


def _try_export_onnx(model, n_features: int, out_path: Path) -> str:
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType

        initial_types = [("float_input", FloatTensorType([None, n_features]))]
        onx = convert_sklearn(model, initial_types=initial_types, target_opset=12)
        out_path.write_bytes(onx.SerializeToString())
        return f"ONNX export saved: {out_path}"
    except ImportError:
        return "ONNX export skipped (install skl2onnx to enable)"
    except Exception as exc:
        return f"ONNX export failed: {exc}"


def main() -> None:
    print("=" * 60)
    print("  PHASE 3 - LIGHTWEIGHT ML TRAINING")
    print("=" * 60)

    data_path = _resolve_data_path()
    X, y, target_col = _load_xy(data_path)

    print(f"Dataset     : {data_path}")
    print(f"Rows        : {len(X):,}")
    print(f"Features    : {X.shape[1]}")
    print(f"Target      : {target_col}")
    print("Label map   : 0=phishing, 1=legitimate")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    models_dir = Path("models")
    models_dir.mkdir(exist_ok=True)

    models = _build_models()
    all_metrics: dict[str, dict[str, float]] = {}

    print("\nTraining models...")
    for name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        metrics = _evaluate(y_test, y_pred)
        all_metrics[name] = metrics

        model_path = models_dir / f"{name}.joblib"
        joblib.dump(model, model_path)

        print(f"  {name:<20} acc={metrics['accuracy']:.4f} f1={metrics['f1']:.4f}")

    best_name = max(all_metrics, key=lambda n: all_metrics[n]["f1"])
    best_model = models[best_name]

    best_model_path = models_dir / "best_model.joblib"
    joblib.dump(best_model, best_model_path)

    summary = {
        "data_path": str(data_path),
        "target_column": target_col,
        "feature_count": int(X.shape[1]),
        "label_mapping": {"0": "phishing", "1": "legitimate"},
        "test_size": 0.2,
        "best_model": best_name,
        "metrics": all_metrics,
    }

    metrics_path = models_dir / "metrics.json"
    metrics_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    onnx_msg = _try_export_onnx(best_model, X.shape[1], models_dir / "best_model.onnx")

    print("\n" + "-" * 60)
    print(f"Best model  : {best_name}")
    print(f"Saved       : {best_model_path}")
    print(f"Metrics     : {metrics_path}")
    print(onnx_msg)
    print("=" * 60)


if __name__ == "__main__":
    main()
