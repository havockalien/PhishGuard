"""
Phase 3 - Inference Endpoints (FastAPI)

Endpoints:
- GET  /health
- POST /predict/url
- POST /predict/features
- POST /predict/batch

Run:
    .\\.venv\\Scripts\\python.exe -m uvicorn inference_api:app --reload --port 8000
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from collections import defaultdict, deque
from typing import Any, Literal

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from feature_extractor import extract_features
from reporting import ThreatReporter


APP_TITLE = "Phishing Inference API"
APP_VERSION = "1.0.0"
MODEL_PATH = "models/best_model.joblib"
ONNX_PATH = "models/best_model.onnx"
API_KEYS = {k.strip() for k in os.getenv("API_KEYS", "dev-key").split(",") if k.strip()}
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "true").lower() == "true"
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))


# Map Phase 2 extractor keys -> dataset/model feature names.
EXTRACTOR_TO_MODEL_FEATURE = {
    "having_IP_Address": "UsingIP",
    "URL_Length": "LongURL",
    "Shortining_Service": "ShortURL",
    "having_At_Symbol": "Symbol@",
    "double_slash_redirecting": "Redirecting//",
    "Pref_suf": "PrefixSuffix-",
    "having_Sub_Domain": "SubDomains",
    "SSLfinal_State": "HTTPS",
    "Domain_registeration_length": "DomainRegLen",
    "Favicon": "Favicon",
    "port": "NonStdPort",
    "HTTPS_token": "HTTPSDomainURL",
    "Request_URL": "RequestURL",
    "URL_of_Anchor": "AnchorURL",
    "Links_in_tags": "LinksInScriptTags",
    "SFH": "ServerFormHandler",
    "Submitting_to_email": "InfoEmail",
    "Abnormal_URL": "AbnormalURL",
    "Redirect": "WebsiteForwarding",
    "on_mouseover": "StatusBarCust",
    "RightClick": "DisableRightClick",
    "popUpWidnow": "UsingPopupWindow",
    "Iframe": "IframeRedirection",
    "age_of_domain": "AgeofDomain",
    "DNSRecord": "DNSRecording",
    "web_traffic": "WebsiteTraffic",
    "Page_Rank": "PageRank",
    "Google_Index": "GoogleIndex",
    "Links_pointing_to_page": "LinksPointingToPage",
    "Statistical_report": "StatsReport",
}


class UrlRequest(BaseModel):
    url: str = Field(..., description="Raw URL to score")
    backend: Literal["sklearn", "onnx"] = "sklearn"
    fetch_page: bool = False


class FeaturesRequest(BaseModel):
    features: dict[str, int]
    backend: Literal["sklearn", "onnx"] = "sklearn"


class BatchRequest(BaseModel):
    items: list[dict[str, Any]] = Field(
        ...,
        description="Each item must include either {'url': '...'} or {'features': {...}}",
        min_length=1,
    )
    backend: Literal["sklearn", "onnx"] = "sklearn"
    fetch_page: bool = False


class PredictRequest(BaseModel):
    url: str = Field(..., description="Raw URL to score")
    backend: Literal["sklearn", "onnx"] = "sklearn"
    fetch_page: bool = False


app = FastAPI(title=APP_TITLE, version=APP_VERSION)
_request_windows: dict[str, deque[float]] = defaultdict(deque)


@app.middleware("http")
async def auth_and_rate_limit(request: Request, call_next):
    path = request.url.path
    is_predict_route = path.startswith("/predict")

    if is_predict_route:
        api_key = request.headers.get("x-api-key", "").strip()
        if REQUIRE_API_KEY and (not api_key or api_key not in API_KEYS):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized: invalid or missing x-api-key"})

        identity = api_key if api_key else (request.client.host if request.client else "anonymous")
        now = time.time()
        window = _request_windows[identity]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= RATE_LIMIT_PER_MINUTE:
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded: max {RATE_LIMIT_PER_MINUTE} requests/min"},
            )
        window.append(now)

    return await call_next(request)


class ModelArtifacts:
    def __init__(self) -> None:
        self.model = joblib.load(MODEL_PATH)
        if not hasattr(self.model, "feature_names_in_"):
            raise RuntimeError("Loaded model does not expose feature_names_in_.")

        self.feature_order = list(self.model.feature_names_in_)
        self.onnx_session = None
        self.onnx_input_name = None

        self._try_load_onnx()

    def _try_load_onnx(self) -> None:
        try:
            import os
            import onnxruntime as ort

            if not os.path.exists(ONNX_PATH):
                return
            self.onnx_session = ort.InferenceSession(ONNX_PATH, providers=["CPUExecutionProvider"])
            self.onnx_input_name = self.onnx_session.get_inputs()[0].name
        except Exception:
            # Keep API usable even if ONNX runtime is unavailable.
            self.onnx_session = None
            self.onnx_input_name = None


artifacts = ModelArtifacts()
threat_reporter = ThreatReporter()


def _is_phishing(pred: int) -> bool:
    return int(pred) == 0


def _handle_phishing_detection(
    *,
    url: str | None,
    pred: int,
    proba_legit: float,
    source: str,
    features: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not _is_phishing(pred):
        return {"triggered": False}

    confidence = 1.0 - float(proba_legit)
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "url": url,
        "label": "phishing",
        "confidence": round(confidence, 6),
        "features": features or {},
    }
    return threat_reporter.report_detection(event)


def _normalize_features(raw_features: dict[str, int]) -> dict[str, int]:
    # Accept either model column names or feature_extractor names.
    normalized: dict[str, int] = {}
    for key, value in raw_features.items():
        mapped = EXTRACTOR_TO_MODEL_FEATURE.get(key, key)
        normalized[mapped] = int(value)
    return normalized


def _row_from_features(raw_features: dict[str, int]) -> pd.DataFrame:
    normalized = _normalize_features(raw_features)
    missing = [c for c in artifacts.feature_order if c not in normalized]
    if missing:
        raise ValueError(f"Missing required features: {missing}")

    row = {c: normalized[c] for c in artifacts.feature_order}
    return pd.DataFrame([row], columns=artifacts.feature_order)


def _predict_with_sklearn(X: pd.DataFrame) -> tuple[int, float]:
    pred = int(artifacts.model.predict(X)[0])
    if hasattr(artifacts.model, "predict_proba"):
        proba_legit = float(artifacts.model.predict_proba(X)[0][1])
    else:
        proba_legit = float(pred)
    return pred, proba_legit


def _predict_with_onnx(X: pd.DataFrame) -> tuple[int, float]:
    if artifacts.onnx_session is None or artifacts.onnx_input_name is None:
        raise RuntimeError("ONNX backend unavailable. Ensure onnxruntime is installed and model exists.")

    X_np = X.to_numpy(dtype=np.float32)
    outputs = artifacts.onnx_session.run(None, {artifacts.onnx_input_name: X_np})

    # skl2onnx classifiers commonly return labels and probabilities.
    label_out = outputs[0]
    pred = int(label_out[0])

    proba_legit = float(pred)
    if len(outputs) > 1:
        probs = outputs[1]
        if isinstance(probs, list) and probs and isinstance(probs[0], dict):
            proba_legit = float(probs[0].get(1, pred))
        elif isinstance(probs, np.ndarray) and probs.ndim == 2 and probs.shape[1] >= 2:
            proba_legit = float(probs[0][1])

    return pred, proba_legit


def _predict(X: pd.DataFrame, backend: Literal["sklearn", "onnx"]) -> tuple[int, float]:
    if backend == "onnx":
        return _predict_with_onnx(X)
    return _predict_with_sklearn(X)


def _response(pred: int, proba_legit: float) -> dict[str, Any]:
    label = "legitimate" if pred == 1 else "phishing"
    return {
        "prediction": int(pred),
        "label": label,
        "probability_legitimate": round(proba_legit, 6),
        "probability_phishing": round(1.0 - proba_legit, 6),
    }


def _predict_response(pred: int, proba_legit: float) -> dict[str, Any]:
    label = "legitimate" if pred == 1 else "phishing"
    confidence = proba_legit if pred == 1 else (1.0 - proba_legit)
    return {"label": label, "confidence": round(float(confidence), 6)}


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "model_path": MODEL_PATH,
        "onnx_path": ONNX_PATH,
        "onnx_available": artifacts.onnx_session is not None,
        "feature_count": len(artifacts.feature_order),
        "api_key_required_on_predict_routes": REQUIRE_API_KEY,
        "rate_limit_per_minute": RATE_LIMIT_PER_MINUTE,
    }


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": APP_TITLE,
        "version": APP_VERSION,
        "status": "ok",
        "endpoints": ["/health", "/predict", "/predict/url", "/predict/features", "/predict/batch", "/docs"],
    }


@app.post("/predict")
def predict(req: PredictRequest) -> dict[str, Any]:
    """Simple Phase 4 contract: {url} -> {label, confidence}."""
    try:
        extracted = extract_features(req.url, fetch_page=req.fetch_page, verbose=False)
        X = _row_from_features(extracted)
        pred, proba_legit = _predict(X, req.backend)
        response = _predict_response(pred, proba_legit)
        response["threat_reporting"] = _handle_phishing_detection(
            url=req.url,
            pred=pred,
            proba_legit=proba_legit,
            source="predict",
            features=X.iloc[0].to_dict(),
        )
        return response
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/predict/url")
def predict_url(req: UrlRequest) -> dict[str, Any]:
    try:
        extracted = extract_features(req.url, fetch_page=req.fetch_page, verbose=False)
        X = _row_from_features(extracted)
        pred, proba_legit = _predict(X, req.backend)
        return {
            "input": {"url": req.url, "backend": req.backend},
            "features": X.iloc[0].to_dict(),
            **_response(pred, proba_legit),
            "threat_reporting": _handle_phishing_detection(
                url=req.url,
                pred=pred,
                proba_legit=proba_legit,
                source="predict/url",
                features=X.iloc[0].to_dict(),
            ),
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/predict/features")
def predict_features(req: FeaturesRequest) -> dict[str, Any]:
    try:
        X = _row_from_features(req.features)
        pred, proba_legit = _predict(X, req.backend)
        return {
            "input": {"backend": req.backend},
            "features": X.iloc[0].to_dict(),
            **_response(pred, proba_legit),
            "threat_reporting": _handle_phishing_detection(
                url=None,
                pred=pred,
                proba_legit=proba_legit,
                source="predict/features",
                features=X.iloc[0].to_dict(),
            ),
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/predict/batch")
def predict_batch(req: BatchRequest) -> dict[str, Any]:
    results: list[dict[str, Any]] = []

    for idx, item in enumerate(req.items):
        try:
            if "url" in item:
                extracted = extract_features(str(item["url"]), fetch_page=req.fetch_page, verbose=False)
                X = _row_from_features(extracted)
                item_url = str(item["url"])
            elif "features" in item and isinstance(item["features"], dict):
                X = _row_from_features(item["features"])
                item_url = None
            else:
                raise ValueError("Item must contain either 'url' or 'features'.")

            pred, proba_legit = _predict(X, req.backend)
            results.append({
                "index": idx,
                "ok": True,
                **_response(pred, proba_legit),
                "threat_reporting": _handle_phishing_detection(
                    url=item_url,
                    pred=pred,
                    proba_legit=proba_legit,
                    source="predict/batch",
                    features=X.iloc[0].to_dict(),
                ),
            })
        except Exception as exc:
            results.append({
                "index": idx,
                "ok": False,
                "error": str(exc),
            })

    return {
        "backend": req.backend,
        "count": len(results),
        "results": results,
    }
