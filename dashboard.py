from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any

import certifi
import pandas as pd
import requests
import streamlit as st
from pymongo import MongoClient, errors as pymongo_errors


st.set_page_config(page_title="Threat Dashboard", page_icon="🛡️", layout="wide")
st.title("Phishing Threat Center")
st.caption("End-user URL scanner + analyst monitoring from MongoDB Atlas")


@st.cache_data(ttl=30)
def load_events(limit: int = 200) -> pd.DataFrame:
    uri = os.getenv("MONGODB_URI", "")
    db_name = os.getenv("MONGODB_DB", "phishing_detection")
    collection_name = os.getenv("MONGODB_COLLECTION", "threat_events")

    if not uri:
        return pd.DataFrame()

    mongo_tls_allow_invalid = os.getenv("MONGODB_TLS_ALLOW_INVALID", "false").lower() == "true"
    client = MongoClient(
        uri,
        tls=True,
        tlsCAFile=certifi.where(),
        tlsAllowInvalidCertificates=mongo_tls_allow_invalid,
        serverSelectionTimeoutMS=20000,
        connectTimeoutMS=20000,
        socketTimeoutMS=20000,
    )
    try:
        try:
            collection = client[db_name][collection_name]
            docs = list(collection.find().sort("_id", -1).limit(limit))
        except pymongo_errors.PyMongoError as exc:
            st.error(f"MongoDB connection failed: {exc}")
            return pd.DataFrame()
    finally:
        client.close()

    if not docs:
        return pd.DataFrame()

    for d in docs:
        d["_id"] = str(d.get("_id"))

    df = pd.DataFrame(docs)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    return df


def list_reports() -> list[Path]:
    reports_dir = Path(os.getenv("REPORTS_DIR", "outputs/reports"))
    if not reports_dir.exists():
        return []
    return sorted(reports_dir.glob("*.pdf"), reverse=True)


def render_report_download(report_path: str | None = None, download_url: str | None = None) -> None:
    if download_url:
        st.link_button("Open PDF report", download_url)
        return

    if not report_path:
        st.info("PDF metadata is present, but no local or remote report link was provided.")
        return

    path = Path(report_path)
    if not path.exists():
        st.info("PDF report path was returned, but file is not available on this machine.")
        return
    with path.open("rb") as f:
        st.download_button(
            label="Download PDF report",
            data=f.read(),
            file_name=path.name,
            mime="application/pdf",
        )


def render_status_chip(ok: bool, success_label: str, failed_label: str) -> None:
    if ok:
        st.success(success_label)
    else:
        st.error(failed_label)


def render_end_user_scanner(api_base_url: str, api_key: str) -> None:
    st.subheader("Scan Suspicious URL")
    st.write("Paste a URL and run an instant phishing check.")

    if "scan_history" not in st.session_state:
        st.session_state.scan_history = []

    with st.form("scan_url_form", clear_on_submit=False):
        url = st.text_input("URL", placeholder="https://example.com/login")
        deep_scan = st.checkbox(
            "Deep scan (fetch page content)",
            value=True,
            help="Uses page-content features for better phishing detection; may be slower.",
        )
        submitted = st.form_submit_button("Scan URL")

    if submitted:
        if not url.strip():
            st.error("Please enter a URL.")
            return

        timeout_seconds = float(os.getenv("SCANNER_TIMEOUT_SECONDS", "60"))

        def call_scanner(fetch_page_flag: bool) -> requests.Response:
            return requests.post(
                f"{api_base_url.rstrip('/')}/predict/url",
                headers={"x-api-key": api_key},
                json={"url": url.strip(), "backend": "sklearn", "fetch_page": fetch_page_flag},
                timeout=timeout_seconds,
            )

        def call_scanner_simple() -> requests.Response:
            return requests.post(
                f"{api_base_url.rstrip('/')}/predict",
                headers={"x-api-key": api_key},
                json={"url": url.strip(), "backend": "sklearn", "fetch_page": False},
                timeout=timeout_seconds,
            )

        try:
            try:
                resp = call_scanner(bool(deep_scan))
            except requests.Timeout as exc:
                if deep_scan:
                    st.warning("Deep scan timed out; retrying with quick scan.")
                    resp = call_scanner(False)
                else:
                    raise exc

            if resp.status_code == 503 and deep_scan:
                st.warning("Deep scan unavailable (503); retrying with quick scan.")
                resp = call_scanner(False)

            if resp.status_code == 503:
                st.warning("URL endpoint unavailable (503); retrying with simple scanner endpoint.")
                resp = call_scanner_simple()

            if resp.status_code != 200:
                try:
                    detail = resp.json().get("detail", resp.text)
                except Exception:
                    detail = resp.text
                st.error(f"Scanner API request failed: {detail}")
                return

            result: dict[str, Any] = resp.json()
            label = str(result.get("label", "unknown"))
            confidence = float(result.get("confidence", 0.0))
            if "probability_phishing" in result:
                phish_conf = float(result.get("probability_phishing", 0.0))
                confidence = phish_conf if label == "phishing" else float(result.get("probability_legitimate", confidence))
            threat_reporting = result.get("threat_reporting", {}) or {}

            st.session_state.scan_history.insert(
                0,
                {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "url": url.strip(),
                    "label": label,
                    "confidence": round(confidence, 6),
                },
            )
            st.session_state.scan_history = st.session_state.scan_history[:20]

            if label == "phishing":
                st.error(f"Result: PHISHING (confidence: {confidence:.2%})")
                st.write("Recommended action: Do not open the URL and report it to your security team.")
            else:
                st.success(f"Result: LEGITIMATE (confidence: {confidence:.2%})")
                st.info("Automated logging/email/PDF are triggered only for phishing detections.")

            if threat_reporting.get("triggered", False):
                st.markdown("### Automated Response Status")
                col1, col2, col3 = st.columns(3)
                with col1:
                    render_status_chip(
                        bool(threat_reporting.get("mongodb", {}).get("ok", False)),
                        "MongoDB logged",
                        "MongoDB logging failed",
                    )
                with col2:
                    render_status_chip(
                        bool(threat_reporting.get("email", {}).get("ok", False)),
                        "Email sent",
                        "Email failed",
                    )
                with col3:
                    render_status_chip(
                        bool(threat_reporting.get("pdf", {}).get("ok", False)),
                        "PDF generated",
                        "PDF failed",
                    )

                pdf_path = str(threat_reporting.get("pdf", {}).get("path", "") or "")
                pdf_url = str(threat_reporting.get("pdf", {}).get("download_url", "") or "")
                s3_uploaded = bool(threat_reporting.get("pdf", {}).get("s3_upload_ok", False))
                if s3_uploaded:
                    st.success("S3 uploaded: true")
                if pdf_url:
                    st.success("Report link ready")
                if pdf_path or pdf_url:
                    render_report_download(report_path=pdf_path if pdf_path else None, download_url=pdf_url if pdf_url else None)
        except requests.Timeout:
            st.error(
                "Could not reach scanner API within timeout. "
                "Try again with Deep scan disabled, or increase SCANNER_TIMEOUT_SECONDS."
            )
        except requests.RequestException as exc:
            st.error(f"Could not reach scanner API: {exc}")

    st.markdown("### Recent Scans")
    if not st.session_state.scan_history:
        st.info("No scans yet in this browser session.")
    else:
        st.dataframe(pd.DataFrame(st.session_state.scan_history), width="stretch")


def render_analyst_dashboard(limit: int) -> None:
    st.subheader("Analyst Dashboard")
    if st.button("Refresh now", key="refresh_analyst"):
        load_events.clear()
        st.rerun()
    df = load_events(limit=limit)

    if df.empty:
        st.warning("No MongoDB events found yet. Ensure MONGODB_URI is configured and detections occurred.")
    else:
        total = len(df)
        phishing_count = int((df.get("label", "") == "phishing").sum()) if "label" in df.columns else total
        unique_urls = int(df["url"].dropna().nunique()) if "url" in df.columns else 0

        c1, c2, c3 = st.columns(3)
        c1.metric("Total Events", total)
        c2.metric("Phishing Events", phishing_count)
        c3.metric("Unique URLs", unique_urls)

        if "source" in df.columns:
            st.markdown("### Events by Source")
            source_counts = df["source"].fillna("unknown").value_counts().reset_index()
            source_counts.columns = ["source", "count"]
            st.bar_chart(source_counts.set_index("source"))

        if "timestamp" in df.columns:
            st.markdown("### Events Over Time")
            timeline = df.dropna(subset=["timestamp"]).copy()
            if not timeline.empty:
                timeline["date"] = timeline["timestamp"].dt.date
                daily = timeline.groupby("date").size().reset_index(name="count")
                st.line_chart(daily.set_index("date"))

        st.markdown("### Latest Events")
        preferred_cols = [
            "timestamp",
            "source",
            "url",
            "label",
            "confidence",
            "_id",
        ]
        show_cols = [c for c in preferred_cols if c in df.columns]
        st.dataframe(df[show_cols], width="stretch")

    st.markdown("### Generated PDF Reports")
    reports = list_reports()
    if not reports:
        st.info("No PDF reports found in outputs/reports yet.")
    else:
        for report in reports[:25]:
            modified = datetime.fromtimestamp(report.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            st.write(f"{report.name} (updated {modified})")


st.sidebar.header("App Settings")
api_base_url = st.sidebar.text_input("Scanner API Base URL", value=os.getenv("API_BASE_URL", "http://127.0.0.1:8000"))
api_key = st.sidebar.text_input("API Key", value=os.getenv("DASHBOARD_API_KEY", "dev-key"), type="password")
limit = st.sidebar.slider("Recent events", min_value=20, max_value=1000, value=200, step=20)

tab_scanner, tab_analyst = st.tabs(["End User Scanner", "Analyst Dashboard"])

with tab_scanner:
    render_end_user_scanner(api_base_url=api_base_url, api_key=api_key)

with tab_analyst:
    render_analyst_dashboard(limit=limit)
