# ============================================================================
# email_parser/parsers/proofpoint_detector.py
# ============================================================================
"""Proofpoint email detection and parsing integration."""

import logging
import re
import base64
from typing import Optional, Tuple, Dict, Any
from email.message import Message
import email.parser
import email.policy


class ProofpointDetector:
    """Detects and processes Proofpoint-wrapped emails."""

    PROOFPOINT_HEADER_MARKER_BEGIN = "---------- Begin Email Headers ----------"
    PROOFPOINT_HEADER_MARKER_END = "---------- End Email Headers ----------"
    PROOFPOINT_BODY_MARKER_BEGIN = "---------- Begin Reported Email ----------"
    PROOFPOINT_BODY_MARKER_END = "---------- End Reported Email ----------"

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def is_proofpoint_email(self, message: Message) -> bool:
        """Detect if this is a Proofpoint-wrapped email."""
        subject = message.get("Subject", "")
        subject_match = subject and "Potential Phish:" in subject

        body_content = self._extract_all_text_content(message)
        body_match = any(
            marker in body_content
            for marker in [
                self.PROOFPOINT_HEADER_MARKER_BEGIN,
                self.PROOFPOINT_HEADER_MARKER_END,
                self.PROOFPOINT_BODY_MARKER_BEGIN,
            ]
        )

        is_proofpoint = subject_match and body_match
        if is_proofpoint:
            self.logger.info("Detected Proofpoint-wrapped email")
        return is_proofpoint

    def extract_proofpoint_content(self, message: Message) -> Optional[Message]:
        """Extract the actual phishing email from Proofpoint wrapper."""
        try:
            self.logger.info("Extracting content from Proofpoint email")
            full_content = self._extract_all_text_content(message)
            if not full_content:
                self.logger.warning("No content found in Proofpoint email")
                return None

            headers_text, reported_content = self._extract_proofpoint_sections(
                full_content
            )
            if not headers_text or not reported_content:
                self.logger.warning("Could not extract Proofpoint sections")
                return None

            reconstructed_email = f"{headers_text}\n\n{reported_content}"
            parser = email.parser.Parser(policy=email.policy.default)
            unwrapped_message = parser.parsestr(reconstructed_email)

            self.logger.info(
                "Successfully extracted Proofpoint content: "
                f"headers={len(headers_text)} chars, "
                f"content={len(reported_content)} chars"
            )
            return unwrapped_message
        except Exception as e:
            self.logger.error(f"Error extracting Proofpoint content: {e}")
            return None

    def _extract_all_text_content(self, message: Message) -> str:
        """Extract all text content from email, including base64-decoded content."""
        all_content: list[str] = []
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                part_content = self._extract_part_content(part)
                if part_content:
                    all_content.append(part_content)
        else:
            content = self._extract_part_content(message)
            if content:
                all_content.append(content)
        return "\n".join(all_content)

    def _extract_part_content(self, part: Message) -> Optional[str]:
        """Extract content from a single message part, handling base64."""
        try:
            encoding = part.get("Content-Transfer-Encoding", "").lower().strip()
            if encoding == "base64":
                self.logger.debug("Processing base64 content for Proofpoint markers")
                raw_payload = part.get_payload(decode=False)
                if isinstance(raw_payload, str):
                    try:
                        decoded_bytes = base64.b64decode(raw_payload)
                        for charset in ["utf-8", "windows-1252", "latin-1"]:
                            try:
                                decoded_text = decoded_bytes.decode(
                                    charset, errors="ignore"
                                )
                                if self._contains_proofpoint_markers(decoded_text):
                                    self.logger.info(
                                        f"Found Proofpoint markers in base64 content using {charset}"
                                    )
                                    return decoded_text
                                break
                            except UnicodeDecodeError:
                                continue
                        else:
                            decoded_text = decoded_bytes.decode(
                                "utf-8", errors="replace"
                            )
                            return decoded_text
                    except Exception as e:
                        self.logger.debug(f"Base64 decode failed: {e}")

            payload = part.get_payload(decode=True)
            if payload is None:
                return None
            if isinstance(payload, bytes):
                charset = part.get_content_charset() or "utf-8"
                try:
                    return payload.decode(charset, errors="ignore")
                except UnicodeDecodeError:
                    return payload.decode("utf-8", errors="replace")
            elif isinstance(payload, str):
                return payload
        except Exception as e:
            self.logger.debug(f"Error extracting part content: {e}")
        return None

    def _contains_proofpoint_markers(self, text: str) -> bool:
        markers = [
            self.PROOFPOINT_HEADER_MARKER_BEGIN,
            self.PROOFPOINT_BODY_MARKER_BEGIN,
            "Potential Phish:",
        ]
        return any(marker in text for marker in markers)

    def _extract_proofpoint_sections(self, text: str) -> Tuple[str, str]:
        headers_text = ""
        reported_content = ""

        header_patterns = [
            rf"{re.escape(self.PROOFPOINT_HEADER_MARKER_BEGIN)}\r?\n(.*?)\r?\n{re.escape(self.PROOFPOINT_HEADER_MARKER_END)}",
            r"[-]{2,15} Begin Email Headers [-]{0,15}\r?\n(.*?)\r?\n[-]{2,15} End Email Headers [-]{0,15}",
            r"Begin Email Headers\s*[-]*\s*\r?\n(.*?)\r?\nEnd Email Headers",
            r"Email Headers:\r?\n[-]{0,15}\r?\n(.*?)\r?\n[-]{0,15}",
        ]
        for pattern in header_patterns:
            headers_match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if headers_match:
                headers_text = headers_match.group(1).strip()
                self.logger.debug(f"Extracted headers using pattern: {pattern[:50]}...")
                break

        content_patterns = [
            rf"{re.escape(self.PROOFPOINT_BODY_MARKER_BEGIN)}\r?\n(.*?)(?:\r?\n{re.escape(self.PROOFPOINT_BODY_MARKER_END)}|$)",
            r"[-]{2,15} Begin Reported Email [-]{0,15}\r?\n(.*?)(?:\r?\n[-]{2,15} End Reported Email [-]{0,15}|$)",
            r"Begin Reported Email\s*[-]*\s*\r?\n(.*?)(?:\r?\nEnd Reported Email|$)",
            r"Reported Email:\r?\n[-]{0,15}\r?\n(.*?)(?:\r?\n[-]{0,15}|$)",
        ]
        for pattern in content_patterns:
            content_match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if content_match:
                reported_content = content_match.group(1).strip()
                self.logger.debug(f"Extracted content using pattern: {pattern[:50]}...")
                break

        self.logger.info(
            "Proofpoint extraction results: "
            f"headers={len(headers_text)} chars, "
            f"content={len(reported_content)} chars"
        )
        return headers_text, reported_content


class EnhancedEmailStructureExtractor:
    """Enhanced version of EmailStructureExtractor with Proofpoint support."""

    def __init__(self, original_extractor, logger: logging.Logger):
        self.original_extractor = original_extractor
        self.logger = logger
        self.proofpoint_detector = ProofpointDetector(logger)

    def extract_structure(
        self, message: Message, depth: int = 0, verbose: bool = False
    ) -> Dict[str, Any]:
        """Enhanced structure extraction that handles Proofpoint emails."""
        if depth == 0 and self.proofpoint_detector.is_proofpoint_email(message):
            self.logger.info("Processing Proofpoint-wrapped email")
            unwrapped_message = self.proofpoint_detector.extract_proofpoint_content(
                message
            )
            if unwrapped_message:
                structure = self.original_extractor.extract_structure(
                    unwrapped_message, depth, verbose
                )
                if verbose:
                    structure["proofpoint_info"] = {
                        "is_proofpoint_wrapped": True,
                        "original_subject": message.get("Subject", ""),
                        "extraction_successful": True,
                    }
                else:
                    if "metadata" not in structure:
                        structure["metadata"] = {}
                    structure["metadata"]["proofpoint_wrapped"] = True
                    structure["metadata"]["proofpoint_extraction_successful"] = True
                return structure
            else:
                self.logger.warning(
                    "Failed to extract Proofpoint content, processing as regular email"
                )
                structure = self.original_extractor.extract_structure(
                    message, depth, verbose
                )
                if verbose:
                    structure["proofpoint_info"] = {
                        "is_proofpoint_wrapped": True,
                        "extraction_successful": False,
                        "extraction_error": "Could not extract wrapped content",
                    }
                else:
                    if "metadata" not in structure:
                        structure["metadata"] = {}
                    structure["metadata"]["proofpoint_wrapped"] = True
                    structure["metadata"]["proofpoint_extraction_successful"] = False
                return structure
        return self.original_extractor.extract_structure(message, depth, verbose)
