from __future__ import annotations

import email
import email.parser
import email.policy
import logging
import os
import sys
from email.message import Message
from typing import Any, Dict, Optional, Union

from .content_analyzer import ContentAnalyzer, FileAnalysis
from .format_detector import EmailFormatDetector

try:
    import extract_msg
    MSG_SUPPORT = True
except Exception:  # pragma: no cover - optional
    MSG_SUPPORT = False


class EmailParser:
    """High level API for parsing email messages."""

    def __init__(self, log_level: int = logging.INFO) -> None:
        self._setup_logging(log_level)
        self.parser = email.parser.Parser(policy=email.policy.default)
        self.bytes_parser = email.parser.BytesParser(policy=email.policy.default)
        self.format_detector = EmailFormatDetector(self.logger)
        self.content_analyzer = ContentAnalyzer(self.logger)

    # ------------------------------------------------------------------
    def _setup_logging(self, level: int) -> None:
        logging.basicConfig(
            level=level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)],
        )
        self.logger = logging.getLogger(__name__)

    # ------------------------------------------------------------------
    def parse(self, input_data: Union[str, bytes], filename: str | None = None) -> Dict[str, Any]:
        if isinstance(input_data, str):
            data_bytes = input_data.encode()
        else:
            data_bytes = input_data

        fmt, conf = self.format_detector.detect_format(data_bytes, filename)

        message = self._parse_message(data_bytes, fmt)
        if not message:
            return {"status": "failed", "errors": ["could not parse message"], "detected_format": fmt}

        structure = self._extract_structure(message)
        return {
            "status": "success",
            "detected_format": fmt,
            "format_confidence": conf,
            "structure": structure,
        }

    # ------------------------------------------------------------------
    def _parse_message(self, data: bytes, fmt: str) -> Optional[Message]:
        if fmt == "msg":
            if not MSG_SUPPORT:
                self.logger.error("MSG support requires extract_msg")
                return None
            return self._parse_msg(data)
        else:
            try:
                return self.bytes_parser.parsebytes(data)
            except Exception as exc:  # pragma: no cover - parse errors
                self.logger.error("Failed to parse EML: %s", exc)
                return None

    # ------------------------------------------------------------------
    def _parse_msg(self, data: bytes) -> Optional[Message]:
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            msg = extract_msg.Message(tmp_path)
            content = self._convert_msg(msg)
            return self.parser.parsestr(content)
        finally:
            os.unlink(tmp_path)

    # ------------------------------------------------------------------
    def _convert_msg(self, msg: Any) -> str:
        lines = [
            f"From: {getattr(msg, 'sender', '')}",
            f"To: {getattr(msg, 'to', '')}",
            f"Subject: {getattr(msg, 'subject', '')}",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=utf-8",
            "",
        ]
        body = getattr(msg, "body", "")
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        lines.append(body)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    def _extract_structure(self, message: Message) -> Dict[str, Any]:
        attachments: list[Dict[str, Any]] = []
        if message.is_multipart():
            for part in message.walk():
                if part.is_multipart():
                    continue
                if part.get_filename():
                    data = part.get_payload(decode=True) or b""
                    info = self.content_analyzer.analyze_content(data, part.get_filename(), part.get_content_type())
                    attachments.append({
                        "filename": part.get_filename(),
                        "analysis": info.__dict__,
                    })
        body = self._get_body_text(message)
        return {"attachment_count": len(attachments), "attachments": attachments, "body_preview": body[:80]}

    # ------------------------------------------------------------------
    def _get_body_text(self, msg: Message) -> str:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode(part.get_content_charset() or "utf-8", "replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                return payload.decode(msg.get_content_charset() or "utf-8", "replace")
        return ""
