from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import certifi
import smtplib
from email.message import EmailMessage
from fpdf import FPDF


class ThreatReporter:
    def __init__(self) -> None:
        self.mongodb_uri = os.getenv("MONGODB_URI", "")
        self.mongodb_db = os.getenv("MONGODB_DB", "phishing_detection")
        self.mongodb_collection = os.getenv("MONGODB_COLLECTION", "threat_events")

        self.smtp_host = os.getenv("SMTP_HOST", "")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.smtp_from = os.getenv("SMTP_FROM", self.smtp_user or "alerts@localhost")
        self.smtp_to = [
            x.strip() for x in os.getenv("SMTP_TO", "").split(",") if x.strip()
        ]
        self.smtp_use_starttls = os.getenv("SMTP_USE_STARTTLS", "true").lower() == "true"

        self.reports_dir = Path(os.getenv("REPORTS_DIR", "outputs/reports"))
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.s3_bucket = os.getenv("REPORTS_S3_BUCKET", "")
        self.s3_prefix = os.getenv("REPORTS_S3_PREFIX", "reports/")
        self.s3_region = os.getenv("REPORTS_S3_REGION", "")
        self.s3_presigned_expiry = int(os.getenv("REPORTS_S3_PRESIGNED_EXPIRY", "3600"))

    def report_detection(self, event: dict[str, Any]) -> dict[str, Any]:
        """Run all reporting steps; never raise so inference remains available."""
        status: dict[str, Any] = {
            "triggered": True,
            "mongodb": {"ok": False, "message": "not_configured"},
            "email": {"ok": False, "message": "not_configured"},
            "pdf": {"ok": False, "message": "not_generated"},
        }

        normalized_event = self._normalize_event(event)

        try:
            insert_result = self._insert_mongodb(normalized_event)
            status["mongodb"] = insert_result
        except Exception as exc:
            status["mongodb"] = {"ok": False, "message": str(exc)}

        try:
            email_result = self._send_email_alert(normalized_event)
            status["email"] = email_result
        except Exception as exc:
            status["email"] = {"ok": False, "message": str(exc)}

        try:
            pdf_result = self._generate_pdf_report(normalized_event)
            status["pdf"] = pdf_result
        except Exception as exc:
            status["pdf"] = {"ok": False, "message": str(exc)}

        return status

    def _normalize_event(self, event: dict[str, Any]) -> dict[str, Any]:
        out = dict(event)
        if not out.get("timestamp"):
            out["timestamp"] = datetime.now(timezone.utc).isoformat()
        out.setdefault("source", "predict")
        out.setdefault("label", "phishing")
        out.setdefault("confidence", 0.0)
        out.setdefault("url", None)
        out.setdefault("features", {})
        return out

    def _insert_mongodb(self, event: dict[str, Any]) -> dict[str, Any]:
        if not self.mongodb_uri:
            return {"ok": False, "message": "MONGODB_URI not set"}

        from pymongo import MongoClient

        mongo_tls_allow_invalid = os.getenv("MONGODB_TLS_ALLOW_INVALID", "false").lower() == "true"
        client = MongoClient(
            self.mongodb_uri,
            tls=True,
            tlsCAFile=certifi.where(),
            tlsAllowInvalidCertificates=mongo_tls_allow_invalid,
            serverSelectionTimeoutMS=20000,
            connectTimeoutMS=20000,
            socketTimeoutMS=20000,
        )
        try:
            collection = client[self.mongodb_db][self.mongodb_collection]
            result = collection.insert_one(event)
            return {"ok": True, "inserted_id": str(result.inserted_id)}
        finally:
            client.close()

    def _send_email_alert(self, event: dict[str, Any]) -> dict[str, Any]:
        if not self.smtp_host or not self.smtp_to:
            return {"ok": False, "message": "SMTP_HOST or SMTP_TO not set"}

        msg = EmailMessage()
        msg["Subject"] = "[ALERT] Phishing URL Detected"
        msg["From"] = self.smtp_from
        msg["To"] = ", ".join(self.smtp_to)

        body = [
            "A phishing detection event was triggered.",
            "",
            f"Time (UTC): {event.get('timestamp')}",
            f"Source: {event.get('source')}",
            f"URL: {event.get('url')}",
            f"Confidence: {event.get('confidence')}",
            "",
            "Top-level features snapshot:",
            str(event.get("features", {})),
        ]
        msg.set_content("\n".join(body))

        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
            if self.smtp_use_starttls:
                server.starttls()
            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)

        return {"ok": True, "message": f"sent_to_{len(self.smtp_to)}_recipient(s)"}

    @staticmethod
    def _pdf_safe_text(value: Any, chunk_size: int = 64) -> str:
        """Insert soft breaks for long unbroken tokens so FPDF can render them."""
        raw = str(value).replace("\r", " ").replace("\n", " ").replace("\t", " ")
        tokens = raw.split(" ")
        normalized_tokens: list[str] = []
        for token in tokens:
            if len(token) <= chunk_size:
                normalized_tokens.append(token)
                continue
            pieces = [token[i:i + chunk_size] for i in range(0, len(token), chunk_size)]
            normalized_tokens.append(" ".join(pieces))
        return " ".join(normalized_tokens)

    def _pdf_write_multicell(self, pdf: FPDF, text: Any, line_height: int) -> None:
        """Write text robustly for core fonts and varying cursor positions."""
        safe = self._pdf_safe_text(text, chunk_size=24)
        # Core Helvetica supports Latin-1; replace unsupported chars instead of failing.
        safe = safe.encode("latin-1", "replace").decode("latin-1")

        # Ensure there is horizontal space before writing.
        pdf.set_x(pdf.l_margin)
        try:
            pdf.multi_cell(0, line_height, safe)
            return
        except Exception:
            pass

        # Fallback: write short fixed-size chunks to guarantee progress.
        for i in range(0, len(safe), 24):
            chunk = safe[i:i + 24]
            if not chunk:
                continue
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, line_height, chunk)

    def _generate_pdf_report(self, event: dict[str, Any]) -> dict[str, Any]:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_name = f"threat_report_{ts}.pdf"
        report_path = self.reports_dir / report_name

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=12)
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Phishing Detection Report", ln=True)

        pdf.set_font("Helvetica", size=11)
        pdf.ln(2)
        self._pdf_write_multicell(pdf, f"Time (UTC): {event.get('timestamp')}", 8)
        self._pdf_write_multicell(pdf, f"Source: {event.get('source')}", 8)
        self._pdf_write_multicell(pdf, f"Label: {event.get('label')}", 8)
        self._pdf_write_multicell(pdf, f"Confidence: {event.get('confidence')}", 8)
        self._pdf_write_multicell(pdf, f"URL: {event.get('url')}", 8)

        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Features", ln=True)
        pdf.set_font("Helvetica", size=10)

        features = event.get("features", {})
        if features:
            for key, value in features.items():
                self._pdf_write_multicell(pdf, f"- {key}: {value}", 7)
        else:
            self._pdf_write_multicell(pdf, "No feature details available.", 7)

        pdf.output(str(report_path))
        out: dict[str, Any] = {"ok": True, "path": str(report_path)}

        if self.s3_bucket:
            try:
                s3_data = self._upload_pdf_to_s3(report_path)
                out.update(s3_data)
            except Exception as exc:
                out["s3_upload_ok"] = False
                out["s3_message"] = str(exc)

        return out

    def _upload_pdf_to_s3(self, report_path: Path) -> dict[str, Any]:
        import boto3
        from botocore.config import Config

        region = self.s3_region or os.getenv("AWS_REGION", "") or os.getenv("AWS_DEFAULT_REGION", "")
        s3_client = boto3.client(
            "s3",
            region_name=region if region else None,
            config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
        )

        normalized_prefix = self.s3_prefix.strip()
        if normalized_prefix and not normalized_prefix.endswith("/"):
            normalized_prefix += "/"
        key = f"{normalized_prefix}{report_path.name}"

        s3_client.upload_file(str(report_path), self.s3_bucket, key, ExtraArgs={"ContentType": "application/pdf"})

        presigned_url = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.s3_bucket, "Key": key},
            ExpiresIn=self.s3_presigned_expiry,
        )

        return {
            "s3_upload_ok": True,
            "s3_bucket": self.s3_bucket,
            "s3_key": key,
            "s3_uri": f"s3://{self.s3_bucket}/{key}",
            "download_url": presigned_url,
            "download_url_expires_in_seconds": self.s3_presigned_expiry,
        }
