# ============================================================================
# email_parser/structure_extractor.py - Enhanced with document processing
# ============================================================================

import email
import base64
import re
from typing import Dict, Any, List, Optional
from email.message import Message
from datetime import datetime
import logging

from .converters import HtmlToTextConverter
from .extractors.document_extractor import DocumentProcessor


class EmailStructureExtractor:
    """Extracts email structure with document text extraction support."""

    def __init__(
        self,
        logger: logging.Logger,
        content_analyzer,
        html_converter: HtmlToTextConverter,
        url_analyzer=None,
        enable_document_processing: bool = True,
    ):
        self.logger = logger
        self.content_analyzer = content_analyzer
        self.html_converter = html_converter
        self.url_analyzer = url_analyzer
        self.document_processor = DocumentProcessor(logger, url_analyzer)
        self.enable_document_processing = enable_document_processing

    def _detect_and_process_proofpoint(self, message: Message) -> Optional[Message]:
        """
        FIXED: Detect and process Proofpoint-wrapped emails.
        Returns the unwrapped message if successful, None otherwise.
        """
        try:
            # Check for Proofpoint indicators
            subject = message.get("Subject", "")
            if "Potential Phish:" not in subject:
                return None

            self.logger.info(
                f"Detected potential Proofpoint email with subject: {subject}"
            )

            # Extract all text content including base64
            full_content = self._extract_proofpoint_content(message)
            if not full_content:
                self.logger.warning(
                    "No content extracted from potential Proofpoint email"
                )
                return None

            # Look for Proofpoint markers
            proofpoint_markers = [
                "---------- Begin Email Headers ----------",
                "---------- Begin Reported Email ----------",
            ]

            marker_found = False
            for marker in proofpoint_markers:
                if marker in full_content:
                    marker_found = True
                    self.logger.info(f"Found Proofpoint marker: {marker}")
                    break

            if not marker_found:
                self.logger.info("No Proofpoint markers found in content")
                return None

            self.logger.info("Found Proofpoint markers, extracting wrapped email...")

            # Extract sections using regex patterns
            headers_text, reported_content = self._extract_proofpoint_sections(
                full_content
            )

            if not headers_text or not reported_content:
                self.logger.warning(
                    f"Failed to extract Proofpoint sections. Headers: {len(headers_text) if headers_text else 0} chars, Content: {len(reported_content) if reported_content else 0} chars"
                )
                return None

            # Reconstruct email
            reconstructed_email = f"{headers_text}\n\n{reported_content}"
            self.logger.info(
                f"Reconstructed email: {len(reconstructed_email)} characters"
            )

            # Parse reconstructed email
            from email.parser import Parser
            import email.policy

            parser = Parser(policy=email.policy.default)

            try:
                unwrapped_message = parser.parsestr(reconstructed_email)
                self.logger.info(
                    f"Successfully unwrapped Proofpoint email. New subject: {unwrapped_message.get('Subject', 'No subject')}"
                )
                return unwrapped_message
            except Exception as parse_error:
                self.logger.error(f"Failed to parse reconstructed email: {parse_error}")
                self.logger.debug(
                    f"Reconstructed email content (first 500 chars): {reconstructed_email[:500]}"
                )
                return None

        except Exception as e:
            self.logger.error(f"Error processing Proofpoint email: {e}")
            import traceback

            self.logger.debug(f"Full traceback: {traceback.format_exc()}")

        return None

    def _extract_proofpoint_content(self, message: Message) -> str:
        """FIXED: Extract all content from Proofpoint email, including base64."""
        all_content = []

        self.logger.debug("Starting Proofpoint content extraction...")

        if message.is_multipart():
            part_count = 0
            for part in message.walk():
                if part.get_content_maintype() == "multipart":
                    continue

                part_count += 1
                self.logger.debug(
                    f"Processing part {part_count}: {part.get_content_type()}"
                )

                content = self._extract_proofpoint_part_content(part)
                if content:
                    all_content.append(content)
                    self.logger.debug(
                        f"Part {part_count}: Extracted {len(content)} characters"
                    )
        else:
            content = self._extract_proofpoint_part_content(message)
            if content:
                all_content.append(content)
                self.logger.debug(f"Single part: Extracted {len(content)} characters")

        result = "\n".join(all_content)
        self.logger.info(
            f"Total Proofpoint content extracted: {len(result)} characters"
        )
        return result

    def _extract_proofpoint_part_content(self, part: Message) -> Optional[str]:
        """FIXED: Extract content from a part, handling base64 for Proofpoint."""
        try:
            encoding = part.get("Content-Transfer-Encoding", "").lower().strip()
            content_type = part.get_content_type()

            self.logger.debug(
                f"Processing part: Content-Type={content_type}, Encoding={encoding}"
            )

            # Special handling for base64 (this is key for Proofpoint)
            if encoding == "base64":
                self.logger.debug("Processing base64 content for Proofpoint...")
                raw_payload = part.get_payload(decode=False)
                if isinstance(raw_payload, str):
                    try:
                        decoded_bytes = base64.b64decode(raw_payload)
                        self.logger.debug(f"Base64 decoded: {len(decoded_bytes)} bytes")

                        # Try UTF-8 first, then fallbacks
                        for charset in ["utf-8", "windows-1252", "latin-1"]:
                            try:
                                decoded_text = decoded_bytes.decode(
                                    charset, errors="ignore"
                                )

                                if any(
                                    marker in decoded_text
                                    for marker in [
                                        "---------- Begin Email Headers ----------",
                                        "---------- Begin Reported Email ----------",
                                        "Potential Phish:",
                                    ]
                                ):
                                    self.logger.info(
                                        f"\u2713 Found Proofpoint content in base64 using {charset}"
                                    )
                                    return decoded_text

                                if len(decoded_text.strip()) > 100:
                                    self.logger.debug(
                                        f"Returning base64 decoded content using {charset}"
                                    )
                                    return decoded_text

                            except UnicodeDecodeError:
                                continue

                    except Exception as e:
                        self.logger.debug(f"Base64 decode failed: {e}")

            payload = part.get_payload(decode=True)
            if payload and isinstance(payload, bytes):
                charset = part.get_content_charset() or "utf-8"
                try:
                    decoded = payload.decode(charset, errors="ignore")
                    if len(decoded.strip()) > 100:
                        self.logger.debug(
                            f"Standard decode successful: {len(decoded)} characters"
                        )
                        return decoded
                except UnicodeDecodeError:
                    decoded = payload.decode("utf-8", errors="replace")
                    return decoded
            elif isinstance(payload, str) and len(payload.strip()) > 100:
                return payload

        except Exception as e:
            self.logger.debug(f"Error extracting Proofpoint part: {e}")

        return None

    def _extract_proofpoint_sections(self, text: str) -> tuple:
        """FIXED: Extract headers and content sections from Proofpoint text."""
        headers_text = ""
        reported_content = ""

        self.logger.debug(
            f"Extracting Proofpoint sections from {len(text)} characters of text"
        )

        header_patterns = [
            r"---------- Begin Email Headers ----------\r?\n(.*?)\r?\n---------- End Email Headers ----------",
            r"[-]{5,} Begin Email Headers [-]{0,}\r?\n(.*?)\r?\n[-]{5,} End Email Headers [-]{0,}",
            r"Begin Email Headers\s*[-]*\s*\r?\n(.*?)\r?\nEnd Email Headers",
            r"Email Headers:\r?\n(.*?)\r?\n(?=---------- Begin Reported Email|$)",
        ]

        for i, pattern in enumerate(header_patterns):
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                headers_text = match.group(1).strip()
                self.logger.info(
                    f"\u2713 Extracted headers using pattern {i+1}: {len(headers_text)} chars"
                )
                break

        content_patterns = [
            r"---------- Begin Reported Email ----------\r?\n(.*?)(?:\r?\n---------- End Reported Email ----------|$)",
            r"[-]{5,} Begin Reported Email [-]{0,}\r?\n(.*?)(?:\r?\n[-]{5,} End Reported Email [-]{0,}|$)",
            r"Begin Reported Email\s*[-]*\s*\r?\n(.*?)(?:\r?\nEnd Reported Email|$)",
            r"Reported Email:\r?\n(.*?)(?:\r?\n(?=---|$)|$)",
        ]

        for i, pattern in enumerate(content_patterns):
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                reported_content = match.group(1).strip()
                self.logger.info(
                    f"\u2713 Extracted content using pattern {i+1}: {len(reported_content)} chars"
                )
                break

        if headers_text:
            self.logger.debug(f"Headers preview: {headers_text[:200]}...")
        else:
            self.logger.warning("No headers extracted!")

        if reported_content:
            self.logger.debug(f"Content preview: {reported_content[:200]}...")
        else:
            self.logger.warning("No reported content extracted!")

        return headers_text, reported_content

    def extract_structure(
        self, message: Message, depth: int = 0, verbose: bool = False
    ) -> Dict[str, Any]:
        """Extract email structure with Proofpoint unwrapping."""

        # CRITICAL: Check for Proofpoint at root level only
        if depth == 0:
            unwrapped_message = self._detect_and_process_proofpoint(message)
            if unwrapped_message:
                self.logger.info(
                    "\u2713 Successfully unwrapped Proofpoint email - processing unwrapped content"
                )

                structure = self.extract_structure(unwrapped_message, depth, verbose)

                if verbose:
                    structure["proofpoint_wrapped"] = True
                    structure["proofpoint_extraction_successful"] = True
                    structure["original_subject"] = message.get("Subject", "")
                else:
                    if "metadata" not in structure:
                        structure["metadata"] = {}
                    structure["metadata"]["proofpoint_wrapped"] = True
                    structure["metadata"]["proofpoint_extraction_successful"] = True
                    structure["metadata"]["original_proofpoint_subject"] = message.get(
                        "Subject", ""
                    )

                return structure
            else:
                subject = message.get("Subject", "")
                if "Potential Phish:" in subject:
                    self.logger.warning(
                        "\u2717 Detected Proofpoint indicators but extraction failed"
                    )
                    structure = (
                        self._extract_streamlined_structure(message, depth)
                        if not verbose
                        else self._extract_verbose_structure(message, depth)
                    )

                    if verbose:
                        structure["proofpoint_wrapped"] = True
                        structure["proofpoint_extraction_successful"] = False
                    else:
                        if "metadata" not in structure:
                            structure["metadata"] = {}
                        structure["metadata"]["proofpoint_wrapped"] = True
                        structure["metadata"][
                            "proofpoint_extraction_successful"
                        ] = False

                    return structure

        self.logger.info(
            f"Extracting email structure at depth {depth}, verbose={verbose}"
        )

        if verbose:
            return self._extract_verbose_structure(message, depth)
        else:
            return self._extract_streamlined_structure(message, depth)

    def _extract_streamlined_structure(
        self, message: Message, depth: int = 0
    ) -> Dict[str, Any]:
        """Extract streamlined email structure with document processing."""
        self.logger.info(f"Extracting streamlined structure at depth {depth}")

        # Build streamlined structure
        if depth == 0:
            # Root level includes metadata and summary
            structure = {
                "metadata": self._build_metadata(message),
                "email": self._build_streamlined_email(message, depth),
                "summary": None,  # Will be populated after processing
                "document_analysis": {
                    "total_documents_processed": 0,
                    "total_text_extracted": 0,
                    "document_urls_found": 0,
                    "extraction_errors": [],
                },
            }

            # Process all documents and collect results if enabled
            if self.enable_document_processing:
                doc_analysis = self._process_all_documents(structure["email"])
                structure["document_analysis"] = doc_analysis

            # Generate summary after email and document processing
            structure["summary"] = self._generate_summary(
                structure["email"],
                doc_analysis if self.enable_document_processing else None,
            )

        else:
            # Nested emails don't need metadata/summary wrapper
            structure = self._build_streamlined_email(message, depth)

        return structure

    def _build_streamlined_email(self, message: Message, depth: int) -> Dict[str, Any]:
        """Build streamlined email object with document processing."""
        self.logger.info(f"Building streamlined email at depth {depth}")

        email_obj = {
            "level": depth,
            "headers": self._extract_streamlined_headers(message),
            "body": self._extract_streamlined_body(message),
            "attachments": [],
            "nested_emails": [],
            "urls": [],
            "document_extracts": [],  # New: Store extracted document text
        }

        # Process attachments and nested emails
        attachments, nested_emails = self._process_attachments_streamlined(
            message, depth
        )
        email_obj["attachments"] = attachments
        email_obj["nested_emails"] = nested_emails

        self.logger.info(
            f"Built email at depth {depth}: {len(attachments)} attachments, {len(nested_emails)} nested emails"
        )

        # Extract URLs if analyzer available and at root level
        if self.url_analyzer and depth == 0:
            email_obj["urls"] = self._extract_urls_streamlined(email_obj)

        return email_obj

    def _detect_nested_email_streamlined(self, part: Message) -> bool:
        """Detect nested emails in streamlined format - ENHANCED with base64 support."""
        content_type = part.get_content_type()
        filename = part.get_filename()

        self.logger.debug(
            f"Streamlined: Checking for nested email - Content-Type: {content_type}, Filename: {filename}"
        )

        # Check content type first
        if content_type in [
            "message/rfc822",
            "message/partial",
            "message/external-body",
        ]:
            self.logger.info(
                f"Streamlined: Detected nested email by content type: {content_type}"
            )
            return True

        # Check filename extensions
        if filename:
            email_extensions = [".eml", ".msg", ".email"]
            for ext in email_extensions:
                if filename.lower().endswith(ext):
                    self.logger.info(
                        f"Streamlined: Detected nested email by filename: {filename}"
                    )
                    return True

        # ENHANCED: Check for base64-encoded email content
        try:
            encoding = part.get("Content-Transfer-Encoding", "").lower().strip()

            if encoding == "base64":
                self.logger.debug(
                    "Streamlined: Checking base64 content for nested email"
                )
                raw_payload = part.get_payload(decode=False)
                if isinstance(raw_payload, str):
                    decoded_content = self._try_decode_base64_email(raw_payload)
                    if decoded_content:
                        self.logger.info(
                            "Streamlined: Found nested email in base64 content!"
                        )
                        return True

            # Also check normally decoded content
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                try:
                    payload_str = payload.decode("utf-8", errors="ignore")
                except UnicodeDecodeError:
                    payload_str = payload.decode("latin-1", errors="ignore")
            else:
                payload_str = str(payload) if payload else ""

            # Check decoded content for email headers
            if self._has_email_headers(payload_str):
                self.logger.info(
                    "Streamlined: Detected nested email by header analysis"
                )
                return True

        except Exception as e:
            self.logger.debug(f"Streamlined: Error in nested email detection: {e}")

        return False

    def _build_streamlined_attachment(
        self, part: Message, depth: int
    ) -> Dict[str, Any]:
        """Build streamlined attachment info with document text extraction and BASE64 EMAIL DETECTION."""

        # Enhanced filename extraction
        filename = self._extract_attachment_filename(part)

        content_type = part.get_content_type()

        attachment = {
            "name": filename,
            "type": "other",  # Will be updated after content analysis
            "size": None,
            "mime_type": content_type,
            "is_inline": "inline" in part.get("Content-Disposition", "").lower(),
            "contains_email": False,
            "document_text": None,  # NEW: Extracted document text
            "document_urls": [],  # NEW: URLs found in document
            "extraction_info": None,  # NEW: Document extraction metadata
            "base64_email_detected": False,  # NEW: Base64 email detection flag
        }

        # Get size and analyze content
        try:
            # Handle message/rfc822 differently - don't decode!
            if content_type == "message/rfc822":
                # For RFC822 messages, the payload is the nested message object
                payload = part.get_payload()  # Don't decode!
                if isinstance(payload, list) and len(payload) > 0:
                    # Size estimation for RFC822 (convert back to string)
                    attachment["size"] = len(str(payload[0])) if payload[0] else 0
                else:
                    attachment["size"] = 0
            else:
                payload = part.get_payload(decode=True)
                if payload:
                    attachment["size"] = len(payload)

                    # Content analysis for hash and type detection
                    analysis = self.content_analyzer.analyze_content(
                        payload, filename, content_type
                    )
                    attachment["hash_md5"] = analysis.hashes.get("md5", "")

                    # Use fingerprinted content type if more confident
                    final_content_type = content_type
                    if analysis.detected_type and analysis.confidence > 0.7:
                        final_content_type = analysis.mime_type
                        self.logger.debug(
                            f"Using fingerprinted content type: {final_content_type}"
                        )

                    # Categorize based on final content type
                    attachment["type"] = self._categorize_attachment_type(
                        final_content_type, filename
                    )
                    
                    # Check if this is actually a MSG file by magic bytes
                    if payload and payload.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
                        attachment["mime_type"] = "application/vnd.ms-outlook"
                        attachment["type"] = "email"

                    # NEW: Process document attachments for text extraction
                    if self.enable_document_processing and self._is_document_type(
                        final_content_type, filename
                    ):
                        self._process_document_attachment(
                            attachment, payload, filename, final_content_type
                        )

            # ENHANCED: Check for nested email INCLUDING BASE64 DETECTION
            if self._detect_nested_email_streamlined(part):
                attachment["contains_email"] = True
                attachment["type"] = "email"  # Override type for emails

                # Try to extract the nested email
                nested_email = self._extract_nested_email_streamlined(part, depth + 1)
                if nested_email:
                    attachment["nested_email"] = nested_email
                    self.logger.info(
                        f"Successfully extracted nested email from attachment: {filename}"
                    )
                else:
                    self.logger.warning(
                        f"Detected nested email but failed to extract: {filename}"
                    )

        except Exception as e:
            self.logger.debug(f"Error analyzing attachment: {e}")

        return attachment

    def _is_document_type(self, content_type: str, filename: str = None) -> bool:
        """Check if attachment is a document type we can extract text from."""
        document_types = [
            "application/pdf",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ]

        # Check content type
        if content_type in document_types:
            return True

        # Check filename extension as fallback
        if filename:
            filename_lower = filename.lower()
            document_extensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx"]
            return any(filename_lower.endswith(ext) for ext in document_extensions)

        return False

    def _process_document_attachment(
        self,
        attachment: Dict[str, Any],
        payload: bytes,
        filename: str,
        content_type: str,
    ) -> None:
        """Process document attachment to extract text and URLs."""
        if not self.enable_document_processing:
            return
        try:
            self.logger.info(f"Processing document attachment: {filename}")

            # Extract text from document
            doc_result = self.document_processor.process_document_attachment(
                payload, filename, content_type
            )

            # Store extraction information
            attachment["extraction_info"] = doc_result["extraction_result"]

            if doc_result["processing_success"]:
                # Store extracted text without truncation
                extracted_text = doc_result["extracted_text"]
                if extracted_text:
                    attachment["document_text"] = extracted_text

                    # Store URLs found in document
                    attachment["document_urls"] = doc_result["urls_found"]

                    # Update attachment type to 'document' if successfully processed
                    if attachment["type"] == "other":
                        attachment["type"] = "document"

                    self.logger.info(
                        f"Successfully extracted {len(extracted_text)} characters "
                        f"and {len(doc_result['urls_found'])} URLs from {filename}"
                    )
            else:
                self.logger.warning(
                    f"Failed to extract text from document {filename}: "
                    f"{doc_result['extraction_result'].get('error_message', 'Unknown error')}"
                )

        except Exception as e:
            self.logger.error(f"Error processing document attachment {filename}: {e}")
            attachment["extraction_info"] = {
                "success": False,
                "error_message": f"Processing failed: {str(e)}",
            }

    def _process_all_documents(self, email_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Process all document attachments in the email structure and collect analysis."""
        if not self.enable_document_processing:
            return {
                "total_documents_processed": 0,
                "total_text_extracted": 0,
                "document_urls_found": 0,
                "extraction_errors": [],
                "document_types_found": [],
                "successful_extractions": [],
                "failed_extractions": [],
            }
        analysis = {
            "total_documents_processed": 0,
            "total_text_extracted": 0,
            "document_urls_found": 0,
            "extraction_errors": [],
            "document_types_found": set(),
            "successful_extractions": [],
            "failed_extractions": [],
        }

        def process_email_documents(email_data: Dict[str, Any]):
            """Recursively process documents in email and nested emails."""

            # Process attachments in current email
            for attachment in email_data.get("attachments", []):
                if attachment.get("extraction_info"):
                    analysis["total_documents_processed"] += 1

                    extraction_info = attachment["extraction_info"]
                    if extraction_info.get("success"):
                        analysis["successful_extractions"].append(
                            {
                                "filename": attachment.get("name"),
                                "document_type": extraction_info.get("document_type"),
                                "extraction_method": extraction_info.get(
                                    "extraction_method"
                                ),
                                "text_length": extraction_info.get("metadata", {}).get(
                                    "character_count", 0
                                ),
                                "urls_found": len(attachment.get("document_urls", [])),
                            }
                        )

                        # Add to totals
                        text_length = extraction_info.get("metadata", {}).get(
                            "character_count", 0
                        )
                        analysis["total_text_extracted"] += text_length
                        analysis["document_urls_found"] += len(
                            attachment.get("document_urls", [])
                        )

                        # Track document types
                        doc_type = extraction_info.get("document_type")
                        if doc_type:
                            analysis["document_types_found"].add(doc_type)
                    else:
                        analysis["failed_extractions"].append(
                            {
                                "filename": attachment.get("name"),
                                "error": extraction_info.get(
                                    "error_message", "Unknown error"
                                ),
                            }
                        )
                        analysis["extraction_errors"].append(
                            f"{attachment.get('name', 'unknown')}: {extraction_info.get('error_message', 'Unknown error')}"
                        )

            # Process nested emails recursively
            for nested_email in email_data.get("nested_emails", []):
                process_email_documents(nested_email)

        # Start processing from root email
        process_email_documents(email_obj)

        # Convert set to list for JSON serialization
        analysis["document_types_found"] = list(analysis["document_types_found"])

        self.logger.info(
            f"Document analysis complete: {analysis['total_documents_processed']} processed, "
            f"{len(analysis['successful_extractions'])} successful, "
            f"{analysis['total_text_extracted']} characters extracted"
        )

        return analysis

    def _extract_urls_streamlined(self, email_obj: Dict[str, Any]) -> List[str]:
        """Extract URLs for streamlined format including document URLs."""
        all_urls = []

        try:
            if self.url_analyzer:
                # Create temporary structure for URL analysis
                temp_structure = {
                    "body": email_obj["body"],
                    "headers": email_obj["headers"],
                    "attachments": email_obj["attachments"],
                    "nested_emails": email_obj["nested_emails"],
                }

                analysis = self.url_analyzer.analyze_email_urls(temp_structure)
                all_urls.extend(analysis.final_urls)

                # Add URLs from document extracts if processing enabled
                if self.enable_document_processing:

                    def collect_document_urls(email_data):
                        for attachment in email_data.get("attachments", []):
                            doc_urls = attachment.get("document_urls", [])
                            all_urls.extend(doc_urls)

                        for nested_email in email_data.get("nested_emails", []):
                            collect_document_urls(nested_email)

                    collect_document_urls(email_obj)

                # Remove duplicates while preserving order
                seen = set()
                unique_urls = []
                for url in all_urls:
                    if url not in seen:
                        seen.add(url)
                        unique_urls.append(url)

                return unique_urls

        except Exception as e:
            self.logger.error(f"Error extracting URLs: {e}")

        return []

    def _generate_summary(
        self, email_obj: Dict[str, Any], doc_analysis: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Generate summary section including document analysis."""

        def collect_emails(
            email, emails_list, subjects_list, timeline_list, forwarding_chain
        ):
            """Recursively collect email info."""
            emails_list.append(email)
            self.logger.debug(
                f"Collected email at level {email.get('level', 'unknown')}: {email.get('headers', {}).get('subject', 'No subject')}"
            )

            if email.get("headers", {}).get("subject"):
                subjects_list.append(email["headers"]["subject"])

            if email.get("headers", {}).get("date"):
                timeline_list.append(email["headers"]["date"])

            # Build forwarding chain
            from_addr = email.get("headers", {}).get("from", "")
            to_addr = email.get("headers", {}).get("to", "")
            if from_addr and to_addr:
                forwarding_chain.append(f"{from_addr} → {to_addr}")

            # Process nested emails recursively
            for nested in email.get("nested_emails", []):
                self.logger.debug(
                    f"Processing nested email from level {email.get('level', 'unknown')}"
                )
                collect_emails(
                    nested, emails_list, subjects_list, timeline_list, forwarding_chain
                )

        all_emails = []
        all_subjects = []
        all_timeline = []
        forwarding_chain = []

        self.logger.info("Starting email collection for summary")
        collect_emails(
            email_obj, all_emails, all_subjects, all_timeline, forwarding_chain
        )
        self.logger.info(f"Collected {len(all_emails)} total emails for summary")

        # Collect domains
        domains = set()
        for email_entry in all_emails:
            for header in ["from", "to", "cc"]:
                value = email_entry.get("headers", {}).get(header, "")
                if "@" in value:
                    try:
                        # Extract domain from email address - handle different formats
                        if "<" in value and ">" in value:
                            # Extract from "Name <email@domain.com>" format
                            email_part = value.split("<")[1].split(">")[0]
                        else:
                            # Direct email format
                            email_part = value

                        if "@" in email_part:
                            domain = email_part.split("@")[1].strip()
                            if domain:
                                domains.add(domain)
                    except Exception:
                        pass

        # Collect attachment types from all emails
        attachment_types = set()
        total_attachments = 0
        for email_entry in all_emails:
            for att in email_entry.get("attachments", []):
                attachment_types.add(att.get("type", "unknown"))
                total_attachments += 1

        # Build summary with document analysis
        summary = {
            "email_chain_length": len(all_emails),
            "attachment_types": sorted(list(attachment_types)),
            "domains_involved": sorted(list(domains)),
            "key_subjects": all_subjects,
            "timeline": sorted(set(all_timeline)),
            "forwarding_chain": forwarding_chain,
            "contains_external_domains": len(domains) > 1,
            "has_suspicious_subject_patterns": any(
                keyword in " ".join(all_subjects).lower()
                for keyword in [
                    "urgent",
                    "action required",
                    "expires",
                    "click here",
                    "verify",
                    "authentication expires",
                ]
            ),
            "authentication_results": self._extract_auth_results(email_obj),
            "total_attachments": total_attachments,
        }

        # Add document analysis to summary if available
        if doc_analysis:
            summary["document_summary"] = {
                "total_documents_processed": doc_analysis["total_documents_processed"],
                "successful_extractions": len(doc_analysis["successful_extractions"]),
                "failed_extractions": len(doc_analysis["failed_extractions"]),
                "total_text_extracted": doc_analysis["total_text_extracted"],
                "document_urls_found": doc_analysis["document_urls_found"],
                "document_types_found": doc_analysis["document_types_found"],
                "has_extractable_documents": doc_analysis["total_documents_processed"]
                > 0,
            }

        self.logger.info(
            f"Summary generated: {len(all_emails)} emails, {total_attachments} attachments, "
            f"{len(domains)} domains, {doc_analysis.get('total_documents_processed', 0) if doc_analysis else 0} documents processed"
        )

        return summary

    # Include all the original helper methods from the previous implementation
    def _extract_streamlined_headers(self, message: Message) -> Dict[str, Any]:
        """Extract essential headers only."""
        headers = {}

        essential_headers = {
            "from": "From",
            "to": "To",
            "subject": "Subject",
            "date": "Date",
            "message_id": "Message-ID",
        }

        for key, header_name in essential_headers.items():
            value = message.get(header_name)
            if value:
                headers[key] = str(value).strip()

        return headers

    def _extract_streamlined_body(self, message: Message) -> Dict[str, Any]:
        """Extract body with streamlined format - ENHANCED for better debugging."""
        body = {"text": None, "html": None, "has_html": False}

        plain_text = None
        html_content = None

        if message.is_multipart():
            self.logger.info(
                f"Processing multipart message with {len(message.get_payload())} parts"
            )

            for i, part in enumerate(message.walk()):
                declared_content_type = part.get_content_type()
                encoding = part.get("Content-Transfer-Encoding", "").lower().strip()

                self.logger.debug(
                    f"Part {i}: Content-Type={declared_content_type}, Encoding={encoding}"
                )

                # Skip the main multipart container
                if declared_content_type.startswith("multipart/"):
                    continue

                # Extract the raw content first
                raw_content = self._extract_text_content(part)
                if not raw_content:
                    self.logger.debug(f"Part {i}: No content extracted")
                    continue

                self.logger.info(f"Part {i}: Extracted {len(raw_content)} characters")

                # VALIDATE: Check if declared content type matches actual content
                validation_result = self._validate_content_type(
                    raw_content, declared_content_type
                )

                if validation_result["is_mismatch"]:
                    self.logger.warning(
                        f"Part {i}: Content type mismatch detected: "
                        f"declared='{declared_content_type}' "
                        f"actual='{validation_result['detected_type']}' "
                        f"confidence={validation_result['confidence']:.2f}"
                    )

                # Use the validated content type for processing
                effective_content_type = validation_result["effective_type"]

                if effective_content_type == "text/html" and not html_content:
                    html_content = raw_content
                    self.logger.info(
                        f"Part {i}: Using as HTML content (declared: {declared_content_type})"
                    )
                elif effective_content_type == "text/plain" and not plain_text:
                    plain_text = raw_content
                    self.logger.info(
                        f"Part {i}: Using as plain text content (declared: {declared_content_type})"
                    )

        else:
            declared_content_type = message.get_content_type()
            encoding = message.get("Content-Transfer-Encoding", "").lower().strip()

            self.logger.info(
                f"Processing single-part message: Content-Type={declared_content_type}, Encoding={encoding}"
            )

            raw_content = self._extract_text_content(message)

            if raw_content:
                self.logger.info(
                    f"Single-part: Extracted {len(raw_content)} characters"
                )

                # VALIDATE: Check single-part content type too
                validation_result = self._validate_content_type(
                    raw_content, declared_content_type
                )

                if validation_result["is_mismatch"]:
                    self.logger.warning(
                        f"Single-part content type mismatch: "
                        f"declared='{declared_content_type}' "
                        f"actual='{validation_result['detected_type']}' "
                        f"confidence={validation_result['confidence']:.2f}"
                    )

                effective_content_type = validation_result["effective_type"]

                if effective_content_type == "text/html":
                    html_content = raw_content
                else:
                    plain_text = raw_content

        # Set body content with preference for plain text if both exist
        if plain_text and plain_text.strip():
            body["text"] = plain_text.strip()
            self.logger.info(f"Using plain text body: {len(body['text'])} characters")
        elif html_content:
            # Convert HTML to text if no plain text available
            converted = self.html_converter.convert(html_content)
            if converted and converted.strip():
                body["text"] = converted.strip()
                self.logger.info(
                    f"Converted HTML to text: {len(body['text'])} characters"
                )

        if html_content and html_content.strip():
            body["has_html"] = True
            # Store truncated HTML for analysis
            if len(html_content) > 500:
                body["html"] = html_content[:500] + "..."
            else:
                body["html"] = html_content
            self.logger.info(f"HTML content detected: {len(html_content)} characters")

        return body

    def _validate_content_type(
        self, content: str, declared_type: str
    ) -> Dict[str, Any]:
        """
        VALIDATE declared content type against actual content.

        Returns:
            {
                'declared_type': str,           # What the header claims
                'detected_type': str,           # What we detected from content
                'effective_type': str,          # What type to use for processing
                'confidence': float,            # Confidence in detection (0.0-1.0)
                'is_mismatch': bool,           # True if declared != detected
                'validation_notes': List[str]   # Reasons for detection
            }
        """
        if not content or not content.strip():
            return {
                "declared_type": declared_type,
                "detected_type": declared_type,
                "effective_type": declared_type,
                "confidence": 1.0,
                "is_mismatch": False,
                "validation_notes": ["Empty content - using declared type"],
            }

        content_sample = content.strip()[:2000]  # Check first 2000 chars
        content_lower = content_sample.lower()
        validation_notes = []

        # Detection scoring system
        html_score = 0.0
        plain_score = 0.0

        # STRONG HTML indicators (high confidence)
        strong_html_patterns = [
            ("<!doctype html", 0.9, "HTML DOCTYPE declaration"),
            ("<html", 0.9, "HTML root element"),
            ("</html>", 0.9, "HTML closing tag"),
            ("<head>", 0.8, "HTML head section"),
            ("<body>", 0.8, "HTML body section"),
            ("<meta ", 0.7, "HTML meta tags"),
            ("xmlns=", 0.7, "XML namespace (HTML email)"),
        ]

        for pattern, score, note in strong_html_patterns:
            if pattern in content_lower:
                html_score = max(html_score, score)
                validation_notes.append(f"Found: {note}")

        # HTML tag counting
        html_tags = re.findall(r"<\w+[^>]*>", content_sample)
        closing_tags = re.findall(r"</\w+>", content_sample)

        if len(html_tags) >= 5:
            tag_score = min(0.8, 0.1 * len(html_tags))
            html_score = max(html_score, tag_score)
            validation_notes.append(f"Found {len(html_tags)} HTML tags")

        if len(closing_tags) >= 2:
            html_score = max(html_score, 0.6)
            validation_notes.append(f"Found {len(closing_tags)} closing tags")

        # HTML entities
        html_entities = re.findall(r"&\w+;", content_sample)
        if len(html_entities) >= 3:
            html_score = max(html_score, 0.5)
            validation_notes.append(f"Found {len(html_entities)} HTML entities")

        # PLAIN TEXT indicators
        plain_indicators = [
            (content_sample.startswith("Dear "), 0.6, "Typical email greeting"),
            (content_sample.startswith("Hello "), 0.5, "Plain text greeting"),
            (content_sample.startswith("Hi "), 0.5, "Casual greeting"),
            (
                "\n\n" in content and "<" not in content[:200],
                0.7,
                "Paragraph breaks without HTML",
            ),
            (
                content.count("\n") > 3 and "<" not in content,
                0.6,
                "Multiple line breaks, no HTML",
            ),
        ]

        for condition, score, note in plain_indicators:
            if condition:
                plain_score = max(plain_score, score)
                validation_notes.append(f"Plain text indicator: {note}")

        # Determine detected type and confidence
        if html_score > plain_score and html_score > 0.5:
            detected_type = "text/html"
            confidence = html_score
        elif plain_score > html_score and plain_score > 0.5:
            detected_type = "text/plain"
            confidence = plain_score
        else:
            # Ambiguous - default to declared type but with low confidence
            detected_type = declared_type
            confidence = 0.3
            validation_notes.append("Ambiguous content - using declared type")

        # Check for mismatch
        is_mismatch = False
        effective_type = declared_type  # Start with declared type

        if declared_type != detected_type:
            # We have a potential mismatch
            if confidence >= 0.7:
                # High confidence detection - use detected type
                is_mismatch = True
                effective_type = detected_type
                validation_notes.append(
                    "High confidence mismatch - using detected type"
                )
            elif confidence >= 0.5:
                # Medium confidence - flag as mismatch but use declared type
                is_mismatch = True
                validation_notes.append(
                    "Medium confidence mismatch - keeping declared type"
                )
            else:
                # Low confidence - just log the uncertainty
                validation_notes.append(
                    "Low confidence detection - using declared type"
                )

        return {
            "declared_type": declared_type,
            "detected_type": detected_type,
            "effective_type": effective_type,
            "confidence": confidence,
            "is_mismatch": is_mismatch,
            "validation_notes": validation_notes,
        }

    def _process_attachments_streamlined(self, message: Message, depth: int) -> tuple:
        """Process attachments with streamlined format - FIXED VERSION."""
        attachments = []
        nested_emails = []

        if not message.is_multipart():
            # CRITICAL FIX: Check single-part messages for nested emails
            if self._detect_nested_email(message):
                self.logger.info("Single-part message contains nested email")
                nested_email = self._extract_nested_email_streamlined(
                    message, depth + 1
                )
                if nested_email:
                    nested_email["source_attachment"] = "embedded_single_part"
                    nested_emails.append(nested_email)
            return attachments, nested_emails

        for part in message.get_payload():
            disposition = part.get("Content-Disposition", "").lower()
            filename = part.get_filename()
            content_type = part.get_content_type()

            # CRITICAL FIX: Clean null bytes from filename
            if filename:
                filename = filename.strip("\x00")

            # ADDITIONAL FIX: Use bool() to avoid None evaluation issues
            is_attachment = "attachment" in disposition or bool(filename)

            # Handle explicit attachments
            if is_attachment:
                attachment = self._build_streamlined_attachment(part, depth)
                attachments.append(attachment)

                # Check for nested email in attachment
                if attachment.get("contains_email"):
                    # Use already extracted nested email if available to avoid duplication
                    nested_email = attachment.get("nested_email")
                    if not nested_email:
                        # Fallback: extract if not already done
                        nested_email = self._extract_nested_email_streamlined(
                            part, depth + 1
                        )
                    if nested_email:
                        nested_email["source_attachment"] = (
                            filename or f"attachment_{len(attachments)}"
                        )
                        nested_emails.append(nested_email)

            # Handle message/rfc822 parts (even if not marked as attachments)
            elif content_type == "message/rfc822":
                self.logger.debug(f"Found message/rfc822 part at depth {depth}")
                nested_email = self._extract_nested_email_streamlined(part, depth + 1)
                if nested_email:
                    nested_email["source_attachment"] = (
                        filename or f"embedded_rfc822_{len(nested_emails)}"
                    )
                    nested_emails.append(nested_email)

            # Handle other parts that might contain nested emails
            elif self._detect_nested_email(part):
                self.logger.debug(
                    f"Found nested email in non-attachment part: {content_type}"
                )
                nested_email = self._extract_nested_email_streamlined(part, depth + 1)
                if nested_email:
                    nested_email["source_attachment"] = (
                        filename or f"embedded_email_{len(nested_emails)}"
                    )
                    nested_emails.append(nested_email)

        return attachments, nested_emails

    def _try_decode_base64_email(self, base64_content: str) -> Optional[str]:
        """Try to decode base64 content and check if it's an email."""
        try:
            # Clean up the base64 string - remove whitespace
            clean_b64 = re.sub(r"\s+", "", base64_content.strip())

            # Decode base64
            decoded_bytes = base64.b64decode(clean_b64)

            # Try to decode as text with different encodings
            for encoding in ["utf-8", "latin-1", "windows-1252"]:
                try:
                    decoded_text = decoded_bytes.decode(encoding, errors="ignore")
                    break
                except UnicodeDecodeError:
                    continue
            else:
                decoded_text = decoded_bytes.decode("utf-8", errors="replace")

            # Check if decoded content looks like an email
            if self._has_email_headers(decoded_text):
                self.logger.info(
                    f"Successfully decoded base64 content as email ({len(decoded_text)} chars)"
                )
                return decoded_text

        except Exception as e:
            self.logger.debug(f"Failed to decode base64 as email: {e}")

        return None

    def _has_email_headers(self, content: str) -> bool:
        """Check if content has email header patterns."""
        if not content or len(content) < 50:
            return False

        email_indicators = [
            "From:",
            "To:",
            "Subject:",
            "Date:",
            "Message-ID:",
            "Received:",
            "Return-Path:",
            "Content-Type:",
        ]

        # Look at first 2000 characters for headers
        content_sample = content[:2000]

        header_count = 0
        for indicator in email_indicators:
            if indicator in content_sample:
                header_count += 1

        self.logger.debug(f"Found {header_count} email header indicators in content")

        # Require at least 3 email headers to consider it an email
        return header_count >= 3

    # Include all remaining helper methods from the original implementation...

    def _extract_attachment_filename(self, part: Message) -> str:
        """Enhanced filename extraction with multiple fallback methods."""
        # Method 1: Standard get_filename()
        filename = part.get_filename()
        if filename:
            filename = filename.strip("\x00").strip()
            if filename and filename != "unknown":
                return filename

        # Method 2: Parse Content-Disposition header manually
        content_disposition = part.get("Content-Disposition", "")
        if content_disposition:
            filename_match = re.search(
                r'filename\s*=\s*["\']?([^"\';\r\n]+)["\']?',
                content_disposition,
                re.IGNORECASE,
            )
            if filename_match:
                filename = filename_match.group(1).strip().strip("\x00")
                if filename:
                    return filename

        # Method 3: Generate filename based on content type
        content_type = part.get_content_type()
        type_extensions = {
            "text/plain": ".txt",
            "text/html": ".html",
            "application/pdf": ".pdf",
            "application/msword": ".doc",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
            "application/vnd.ms-excel": ".xls",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
        }

        extension = type_extensions.get(content_type, "")
        if "/" in content_type:
            base_name = content_type.split("/")[1].replace("-", "_")
        else:
            base_name = "attachment"

        return f"{base_name}{extension}" if extension else f"{base_name}_file"

    def _categorize_attachment_type(self, content_type: str, filename: str) -> str:
        """Categorize attachment type for streamlined output."""
        # Check detected mime type from content analysis first
        if content_type.startswith("image/"):
            return "image"
        elif content_type.startswith("video/"):
            return "video"
        elif content_type.startswith("audio/"):
            return "audio"
        elif content_type in ["message/rfc822", "application/vnd.ms-outlook"]:
            return "email"
        elif content_type.startswith("text/"):
            return "text"
        elif "pdf" in content_type:
            return "document"
        elif any(x in content_type for x in ["word", "excel", "powerpoint", "office"]):
            return "document"
        elif "zip" in content_type or "archive" in content_type:
            return "archive"
        elif "executable" in content_type or (filename and filename.endswith(".exe")):
            return "executable"
        else:
            return "other"

    def _extract_nested_email_streamlined(
        self, part: Message, depth: int
    ) -> Optional[Dict[str, Any]]:
        """Extract nested email with base64 and MSG support - ENHANCED for streamlined format."""
        try:
            nested_message = None
            content_type = part.get_content_type()
            filename = part.get_filename()

            if content_type == "message/rfc822":
                # Standard RFC822 handling
                payload_list = part.get_payload()
                if isinstance(payload_list, list) and len(payload_list) > 0:
                    nested_message = payload_list[0]
                else:
                    return None
            elif content_type == "application/vnd.ms-outlook" or (filename and filename.lower().endswith('.msg')):
                # Handle MSG attachments
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes) and payload.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
                    self.logger.info(f"Processing nested MSG file: {filename}")
                    # Use the EmailParser to handle MSG files
                    from .parser import EmailParser
                    from .parsers.msg_parser import MsgFormatParser
                    from .parsers.eml_parser import EmlFormatParser
                    from .converters import HtmlToTextConverter
                    from .normalizers import Utf16ContentNormalizer
                    
                    # Create necessary components
                    content_normalizer = Utf16ContentNormalizer(self.logger)
                    html_converter = HtmlToTextConverter(self.logger)
                    
                    # Create MSG parser
                    msg_parser = MsgFormatParser(
                        self.logger, 
                        content_normalizer, 
                        html_converter, 
                        self.content_analyzer
                    )
                    
                    # Parse the MSG file directly
                    nested_message = msg_parser.parse(payload, filename)
                    if nested_message:
                        self.logger.info(f"Successfully parsed nested MSG file at depth {depth}")
                    else:
                        self.logger.warning(f"Failed to parse nested MSG file: {filename}")
                else:
                    self.logger.warning(f"MSG attachment doesn't have valid magic bytes: {filename}")
            else:
                # ENHANCED: Check for base64-encoded emails first
                encoding = part.get("Content-Transfer-Encoding", "").lower().strip()

                if encoding == "base64":
                    # Try to decode base64 content as email
                    raw_payload = part.get_payload(decode=False)
                    if isinstance(raw_payload, str):
                        decoded_email_text = self._try_decode_base64_email(raw_payload)
                        if decoded_email_text:
                            # Parse the decoded email text
                            from email.parser import Parser

                            parser = Parser(policy=email.policy.default)
                            nested_message = parser.parsestr(decoded_email_text)
                            self.logger.info(
                                f"Streamlined: Successfully parsed base64-encoded email at depth {depth}"
                            )

                # Fallback to standard decoding if base64 didn't work
                if not nested_message:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        # Check for MSG magic bytes
                        if payload.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
                            self.logger.info("Detected MSG file in decoded payload")
                            # Parse as MSG
                            from .parsers.msg_parser import MsgFormatParser
                            from .converters import HtmlToTextConverter
                            from .normalizers import Utf16ContentNormalizer
                            
                            content_normalizer = Utf16ContentNormalizer(self.logger)
                            html_converter = HtmlToTextConverter(self.logger)
                            msg_parser = MsgFormatParser(
                                self.logger, 
                                content_normalizer, 
                                html_converter, 
                                self.content_analyzer
                            )
                            nested_message = msg_parser.parse(payload, filename)
                        else:
                            # Try parsing as EML
                            from email.parser import BytesParser
                            parser = BytesParser(policy=email.policy.default)
                            nested_message = parser.parsebytes(payload)
                    elif isinstance(payload, str):
                        from email.parser import Parser
                        parser = Parser(policy=email.policy.default)
                        nested_message = parser.parsestr(payload)
                    else:
                        return None

            if nested_message:
                return self._build_streamlined_email(nested_message, depth)

        except Exception as e:
            self.logger.error(
                f"Streamlined: Error extracting nested email at depth {depth}: {e}"
            )
            import traceback
            self.logger.debug(f"Traceback: {traceback.format_exc()}")

        return None

    def _detect_nested_email(self, part: Message) -> bool:
        """Detect if a part contains a nested email - ENHANCED with base64 support."""
        content_type = part.get_content_type()
        filename = part.get_filename()

        self.logger.debug(
            f"Checking for nested email - Content-Type: {content_type}, Filename: {filename}"
        )

        # Check content type first
        if content_type in [
            "message/rfc822",
            "message/partial",
            "message/external-body",
        ]:
            self.logger.info(f"Detected nested email by content type: {content_type}")
            return True

        # Check filename extensions
        if filename:
            email_extensions = [".eml", ".msg", ".email"]
            for ext in email_extensions:
                if filename.lower().endswith(ext):
                    self.logger.info(f"Detected nested email by filename: {filename}")
                    return True

        # ENHANCED: Check for base64-encoded email content
        try:
            encoding = part.get("Content-Transfer-Encoding", "").lower().strip()

            if encoding == "base64":
                self.logger.debug("Checking base64 content for nested email")
                raw_payload = part.get_payload(decode=False)
                if isinstance(raw_payload, str):
                    decoded_content = self._try_decode_base64_email(raw_payload)
                    if decoded_content:
                        self.logger.info("Found nested email in base64 content!")
                        return True

            # Also check normally decoded content
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                try:
                    payload_str = payload.decode("utf-8", errors="ignore")
                except UnicodeDecodeError:
                    payload_str = payload.decode("latin-1", errors="ignore")
            else:
                payload_str = str(payload) if payload else ""

            # Check decoded content for email headers
            if self._has_email_headers(payload_str):
                return True

        except Exception as e:
            self.logger.debug(f"Error in nested email detection: {e}")

        return False

    def _extract_text_content(self, part: Message) -> Optional[str]:
        """Extract and decode text content from a message part."""
        try:
            payload = part.get_payload(decode=True)

            if payload is None:
                payload = part.get_payload(decode=False)
                if isinstance(payload, list):
                    return None

            if isinstance(payload, bytes):
                charset = part.get_content_charset() or "utf-8"

                try:
                    content = payload.decode(charset, errors="ignore")
                except (UnicodeDecodeError, LookupError):
                    for fallback_charset in ["utf-8", "latin1", "cp1252"]:
                        try:
                            content = payload.decode(fallback_charset, errors="ignore")
                            break
                        except (UnicodeDecodeError, LookupError):
                            continue
                    else:
                        content = payload.decode("utf-8", errors="replace")

            elif isinstance(payload, str):
                content = payload
            else:
                content = str(payload)

            return content

        except Exception as e:
            self.logger.error(f"Error extracting text content: {e}")
            return None

    def _build_metadata(self, message: Message) -> Dict[str, Any]:
        """Build metadata section."""
        total_emails, total_attachments, max_depth = self._count_structure(message, 0)

        return {
            "parser_version": "2.1",  # Updated version
            "parsed_at": datetime.utcnow().isoformat() + "Z",
            "source_file": "unknown",
            "total_depth": max_depth,
            "total_emails": total_emails,
            "total_attachments": total_attachments,
        }

    def _count_structure(self, message: Message, current_depth: int) -> tuple:
        """Count total emails, attachments, and max depth."""
        email_count = 1
        attachment_count = 0
        max_depth = current_depth

        if message.is_multipart():
            for part in message.get_payload():
                disposition = part.get("Content-Disposition", "").lower()
                content_type = part.get_content_type()

                if "attachment" in disposition or bool(part.get_filename()):
                    attachment_count += 1

                    if self._detect_nested_email(part):
                        try:
                            if part.get_content_type() == "message/rfc822":
                                nested_message = part.get_payload(0)
                            else:
                                payload = part.get_payload(decode=True)
                                if isinstance(payload, bytes):
                                    from email.parser import BytesParser

                                    parser = BytesParser(policy=email.policy.default)
                                    nested_message = parser.parsebytes(payload)
                                else:
                                    continue

                            if nested_message:
                                nested_emails, nested_attachments, nested_depth = (
                                    self._count_structure(
                                        nested_message, current_depth + 1
                                    )
                                )
                                email_count += nested_emails
                                attachment_count += nested_attachments
                                max_depth = max(max_depth, nested_depth)

                        except Exception:
                            pass

                elif content_type == "message/rfc822":
                    try:
                        nested_message = part.get_payload(0)
                        if nested_message:
                            nested_emails, nested_attachments, nested_depth = (
                                self._count_structure(nested_message, current_depth + 1)
                            )
                            email_count += nested_emails
                            attachment_count += nested_attachments
                            max_depth = max(max_depth, nested_depth)
                    except Exception:
                        pass

        return email_count, attachment_count, max_depth

    def _extract_auth_results(self, email_obj: Dict[str, Any]) -> Dict[str, str]:
        """Extract authentication results from headers."""
        return {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

    # Include verbose mode methods for backward compatibility...
    def _extract_verbose_structure(
        self, message: Message, depth: int = 0
    ) -> Dict[str, Any]:
        """Keep original verbose implementation for backward compatibility."""
        """Extract comprehensive email structure with attachments and nested emails (original verbose format)."""
        self.logger.info(f"Extracting verbose email structure at depth {depth}")

        structure = {
            "type": "email",
            "depth": depth,
            "headers": self._extract_headers(message),
            "content_info": self._analyze_content_type(message),
            "body": self._extract_email_body(message),
            "parts": [],
            "attachments": [],
            "nested_emails": [],
            "part_count": 0,
            "attachment_count": 0,
            "nested_email_count": 0,
            "url_analysis": None,
        }

        try:
            if message.is_multipart():
                self.logger.info(
                    f"Processing multipart message with {len(message.get_payload())} parts"
                )

                for i, part in enumerate(message.get_payload()):
                    self.logger.debug(f"Processing part {i} at depth {depth}")

                    part_info = {
                        "part_index": i,
                        "content_type": part.get_content_type(),
                        "content_disposition": part.get("Content-Disposition"),
                        "filename": part.get_filename(),
                        "is_attachment": False,
                        "is_nested_email": False,
                    }

                    disposition = part.get("Content-Disposition", "").lower()
                    # FIXED: Use bool() to avoid None evaluation issues
                    if "attachment" in disposition or bool(part.get_filename()):
                        part_info["is_attachment"] = True
                        attachment = self._parse_attachment(part, depth)
                        structure["attachments"].append(attachment)

                        if attachment.get("is_nested_email"):
                            structure["nested_emails"].append(
                                attachment["nested_email"]
                            )
                            structure["nested_email_count"] += 1

                        structure["attachment_count"] += 1

                    structure["parts"].append(part_info)
                    structure["part_count"] += 1
            else:
                self.logger.info("Processing single-part message")
                if self._detect_nested_email(message):
                    self.logger.info("Single-part message contains nested email")
                    attachment = self._parse_attachment(message, depth)
                    structure["attachments"].append(attachment)
                    if attachment.get("is_nested_email"):
                        structure["nested_emails"].append(attachment["nested_email"])
                        structure["nested_email_count"] += 1
                    structure["attachment_count"] += 1

            # Add URL analysis if analyzer is available (only at top level to avoid recursion)
            if self.url_analyzer and depth == 0:
                try:
                    self.logger.info("Performing URL analysis on email structure")
                    url_analysis = self.url_analyzer.analyze_email_urls(structure)
                    structure["url_analysis"] = (
                        self.url_analyzer.get_serializable_analysis(url_analysis)
                    )
                    self.logger.info(
                        f"URL analysis complete: {structure['url_analysis']['summary']}"
                    )
                except Exception as e:
                    self.logger.error(f"Error during URL analysis: {e}")
                    structure["url_analysis"] = {"error": str(e)}

        except Exception as e:
            self.logger.error(f"Error extracting email structure: {e}")
            structure["parsing_error"] = str(e)

        self.logger.info(
            f"Completed structure extraction at depth {depth}: "
            f"{structure['part_count']} parts, "
            f"{structure['attachment_count']} attachments, "
            f"{structure['nested_email_count']} nested emails"
        )

        return structure

    # Keep all original helper methods for verbose mode
    def _extract_headers(self, message: Message) -> Dict[str, Any]:
        """Extract and analyze email headers."""
        self.logger.debug("Extracting headers...")
        headers = {}

        try:
            standard_headers = [
                "From",
                "To",
                "Cc",
                "Bcc",
                "Subject",
                "Date",
                "Message-ID",
                "Content-Type",
                "Content-Transfer-Encoding",
            ]

            for header in standard_headers:
                value = message.get(header)
                if value:
                    headers[header.lower().replace("-", "_")] = str(value)
                    self.logger.debug(f"Found header {header}: {value}")

            all_headers = {}
            for key, value in message.items():
                all_headers[key.lower().replace("-", "_")] = str(value)

            headers["all_headers"] = all_headers
            headers["header_count"] = len(all_headers)

            self.logger.info(f"Extracted {len(all_headers)} headers")

        except Exception as e:
            self.logger.error(f"Error extracting headers: {e}")
            headers["error"] = f"Header extraction failed: {e}"

        return headers

    def _analyze_content_type(self, message: Message) -> Dict[str, Any]:
        """Analyze content type and encoding information."""
        self.logger.debug("Analyzing content type...")

        content_info = {
            "content_type": "unknown",
            "main_type": "unknown",
            "sub_type": "unknown",
            "charset": None,
            "boundary": None,
            "encoding": None,
            "is_multipart": False,
        }

        try:
            content_type = message.get_content_type()
            content_info["content_type"] = content_type
            content_info["main_type"] = message.get_content_maintype()
            content_info["sub_type"] = message.get_content_subtype()
            content_info["is_multipart"] = message.is_multipart()

            charset = message.get_content_charset()
            if charset:
                content_info["charset"] = charset

            if content_info["is_multipart"]:
                boundary = message.get_boundary()
                if boundary:
                    content_info["boundary"] = boundary

            encoding = message.get("Content-Transfer-Encoding")
            if encoding:
                content_info["encoding"] = encoding

            self.logger.debug(f"Content type analysis: {content_info}")

        except Exception as e:
            self.logger.error(f"Error analyzing content type: {e}")
            content_info["error"] = f"Content type analysis failed: {e}"

        return content_info

    def _extract_email_body(self, message: Message) -> Dict[str, Any]:
        """Extract email body content with HTML conversion - with content type validation for verbose mode."""
        self.logger.debug("Extracting email body content...")

        body_info = {
            "plain_text": None,
            "html_content": None,
            "body_type": "none",
            "truncated": False,
            "char_count": 0,
            "content_type_validation": [],  # NEW: Track validation results
        }

        try:
            if message.is_multipart():
                self.logger.debug("Processing multipart message for body extraction")

                for part in message.walk():
                    declared_content_type = part.get_content_type()

                    raw_content = self._extract_text_content(part)
                    if not raw_content:
                        continue

                    # VALIDATE content type
                    validation_result = self._validate_content_type(
                        raw_content, declared_content_type
                    )
                    body_info["content_type_validation"].append(validation_result)

                    if validation_result["is_mismatch"]:
                        self.logger.warning(
                            f"Content type mismatch in multipart: {validation_result}"
                        )

                    effective_content_type = validation_result["effective_type"]

                    if (
                        effective_content_type == "text/plain"
                        and not body_info["plain_text"]
                    ):
                        body_info["plain_text"] = raw_content.strip()
                        body_info["body_type"] = "plain"
                        body_info["char_count"] = len(body_info["plain_text"])
                        self.logger.debug(
                            f"Found plain text body ({body_info['char_count']} chars)"
                        )

                    elif (
                        effective_content_type == "text/html"
                        and not body_info["html_content"]
                    ):
                        body_info["html_content"] = raw_content.strip()
                        self.logger.debug(
                            f"Found HTML body ({len(body_info['html_content'])} chars)"
                        )

                        if not body_info["plain_text"]:
                            plain_from_html = self.html_converter.convert(
                                body_info["html_content"]
                            )
                            if plain_from_html and plain_from_html.strip():
                                body_info["plain_text"] = plain_from_html.strip()
                                body_info["body_type"] = "html_converted"
                                body_info["char_count"] = len(body_info["plain_text"])
                                self.logger.debug(
                                    f"Converted HTML to text ({body_info['char_count']} chars)"
                                )
            else:
                declared_content_type = message.get_content_type()
                self.logger.debug(
                    f"Processing single-part message: {declared_content_type}"
                )

                raw_content = self._extract_text_content(message)
                if raw_content:
                    raw_content = raw_content.strip()

                    # VALIDATE content type
                    validation_result = self._validate_content_type(
                        raw_content, declared_content_type
                    )
                    body_info["content_type_validation"].append(validation_result)

                    if validation_result["is_mismatch"]:
                        self.logger.warning(
                            f"Content type mismatch in single-part: {validation_result}"
                        )

                    effective_content_type = validation_result["effective_type"]

                    if effective_content_type == "text/plain":
                        body_info["plain_text"] = raw_content
                        body_info["body_type"] = "plain"
                        body_info["char_count"] = len(raw_content)
                    elif effective_content_type == "text/html":
                        body_info["html_content"] = raw_content
                        plain_from_html = self.html_converter.convert(raw_content)
                        if plain_from_html and plain_from_html.strip():
                            body_info["plain_text"] = plain_from_html.strip()
                            body_info["body_type"] = "html_converted"
                            body_info["char_count"] = len(body_info["plain_text"])
                    else:
                        body_info["plain_text"] = raw_content
                        body_info["body_type"] = "unknown"
                        body_info["char_count"] = len(raw_content)

            # Handle HTML content truncation for output
            if body_info["html_content"] and len(body_info["html_content"]) > 50:
                body_info["html_preview"] = (
                    body_info["html_content"][:50]
                    + "... [HTML CONTENT TRUNCATED FOR BREVITY]"
                )
                body_info["truncated"] = True
                del body_info["html_content"]
            elif body_info["html_content"]:
                body_info["html_preview"] = (
                    body_info["html_content"] + " [HTML CONTENT DETECTED]"
                )
                del body_info["html_content"]

            self.logger.info(
                f"Body extraction complete: type={body_info['body_type']}, "
                f"chars={body_info['char_count']}, truncated={body_info['truncated']}"
            )

        except Exception as e:
            self.logger.error(f"Error extracting email body: {e}")
            body_info["error"] = str(e)

        return body_info

    def _extract_text_content(self, part: Message) -> Optional[str]:
        """Extract and decode text content from a message part - FIXED for base64."""
        try:
            # CRITICAL FIX: Handle base64 encoding properly
            encoding = part.get("Content-Transfer-Encoding", "").lower().strip()

            # Get the payload - but handle base64 differently
            if encoding == "base64":
                # For base64, get raw payload first, then decode manually
                raw_payload = part.get_payload(decode=False)  # Get raw base64 string
                if isinstance(raw_payload, list):
                    return None

                try:
                    import base64

                    # Decode base64 manually
                    decoded_bytes = base64.b64decode(raw_payload)
                    self.logger.debug(
                        f"Successfully decoded base64 content: {len(decoded_bytes)} bytes"
                    )
                    payload = decoded_bytes
                except Exception as e:
                    self.logger.warning(
                        f"Manual base64 decode failed: {e}, falling back to get_payload(decode=True)"
                    )
                    payload = part.get_payload(decode=True)
            else:
                # For other encodings, use standard method
                payload = part.get_payload(decode=True)

            # Handle the case where payload is still None or a list
            if payload is None:
                payload = part.get_payload(decode=False)
                if isinstance(payload, list):
                    return None

            # Convert bytes to string with proper charset handling
            if isinstance(payload, bytes):
                charset = part.get_content_charset() or "utf-8"

                try:
                    content = payload.decode(charset, errors="ignore")
                    self.logger.debug(
                        f"Decoded {len(payload)} bytes using charset {charset}"
                    )
                except (UnicodeDecodeError, LookupError):
                    # Try fallback charsets
                    for fallback_charset in [
                        "utf-8",
                        "latin1",
                        "cp1252",
                        "windows-1252",
                    ]:
                        try:
                            content = payload.decode(fallback_charset, errors="ignore")
                            self.logger.debug(
                                f"Successfully decoded using fallback charset {fallback_charset}"
                            )
                            break
                        except (UnicodeDecodeError, LookupError):
                            continue
                    else:
                        content = payload.decode("utf-8", errors="replace")
                        self.logger.warning(
                            "Used UTF-8 with errors='replace' as final fallback"
                        )

            elif isinstance(payload, str):
                content = payload
            else:
                content = str(payload)

            # ADDITIONAL FIX: Clean up common base64 artifacts
            if encoding == "base64" and content:
                # Remove any stray base64 padding or whitespace that might remain
                content = content.strip()

                # Log successful extraction
                self.logger.info(
                    f"Successfully extracted and decoded {encoding} content: {len(content)} characters"
                )

            return content

        except Exception as e:
            self.logger.error(f"Error extracting text content: {e}")
            return None

    def _detect_nested_email(self, part: Message) -> bool:
        """Detect if a part contains a nested email."""
        content_type = part.get_content_type()
        filename = part.get_filename()

        self.logger.debug(
            f"Checking for nested email - Content-Type: {content_type}, Filename: {filename}"
        )

        # CRITICAL: Check content type first - this should catch message/rfc822
        if content_type in [
            "message/rfc822",
            "message/partial",
            "message/external-body",
        ]:
            self.logger.info(f"Detected nested email by content type: {content_type}")
            return True

        if filename:
            email_extensions = [".eml", ".msg", ".email"]
            for ext in email_extensions:
                if filename.lower().endswith(ext):
                    self.logger.info(f"Detected nested email by filename: {filename}")
                    return True

        try:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                try:
                    payload_str = payload.decode("utf-8")
                except UnicodeDecodeError:
                    payload_str = payload.decode("latin-1", errors="ignore")
            else:
                payload_str = str(payload)

            email_indicators = [
                "From:",
                "To:",
                "Subject:",
                "Date:",
                "Message-ID:",
                "Received:",
                "Return-Path:",
            ]
            header_matches = {}

            for indicator in email_indicators:
                if indicator in payload_str[:2000]:
                    header_matches[indicator] = payload_str.find(indicator)

            header_count = len(header_matches)
            self.logger.debug(
                f"Found email headers: {list(header_matches.keys())} (count: {header_count})"
            )

            if header_count >= 3:
                self.logger.info(
                    f"Detected nested email by header pattern analysis ({header_count} headers found)"
                )
                return True

        except Exception as e:
            self.logger.debug(f"Error in nested email detection: {e}")

        return False

    def _parse_attachment(self, part: Message, depth: int = 0) -> Dict[str, Any]:
        """Parse individual attachment with content analysis."""
        self.logger.info(f"Parsing attachment at depth {depth}")

        attachment_info = {
            "type": "attachment",
            "depth": depth,
            "content_type": part.get_content_type(),
            "filename": part.get_filename(),
            "size": None,
            "encoding": part.get("Content-Transfer-Encoding"),
            "is_nested_email": False,
            "nested_email": None,
            "content_disposition": part.get("Content-Disposition"),
            "content_analysis": {},
        }

        try:
            payload = part.get_payload(decode=True)
            if payload:
                attachment_info["size"] = len(payload)

                self.logger.debug(
                    f"Performing content analysis for attachment: {attachment_info['filename']}"
                )
                content_analysis = self.content_analyzer.analyze_content(
                    payload,
                    attachment_info["filename"],
                    attachment_info["content_type"],
                )

                attachment_info["content_analysis"] = content_analysis.__dict__

                if content_analysis.detected_type and content_analysis.confidence > 0.7:
                    if content_analysis.mime_type != attachment_info["content_type"]:
                        self.logger.info(
                            f"Content analysis override: {attachment_info['content_type']} -> {content_analysis.mime_type}"
                        )
                        attachment_info["fingerprinted_content_type"] = (
                            content_analysis.mime_type
                        )

            if self._detect_nested_email(part):
                attachment_info["is_nested_email"] = True
                self.logger.info("Processing nested email attachment")

                try:
                    if part.get_content_type() == "message/rfc822":
                        nested_payload = (
                            part.get_payload(0) if part.get_payload() else None
                        )
                    else:
                        nested_payload = part.get_payload(decode=True)
                        if isinstance(nested_payload, bytes):
                            from email.parser import BytesParser

                            parser = BytesParser(policy=email.policy.default)
                            nested_message = parser.parsebytes(nested_payload)
                        else:
                            from email.parser import Parser

                            parser = Parser(policy=email.policy.default)
                            nested_message = parser.parsestr(str(nested_payload))
                        nested_payload = nested_message

                    if nested_payload:
                        attachment_info["nested_email"] = self.extract_structure(
                            nested_payload, depth + 1, verbose=True
                        )
                        self.logger.info(
                            f"Successfully parsed nested email at depth {depth + 1}"
                        )

                except Exception as e:
                    self.logger.error(f"Failed to parse nested email: {e}")
                    attachment_info["nested_email_error"] = str(e)

        except Exception as e:
            self.logger.error(f"Error parsing attachment: {e}")
            attachment_info["error"] = str(e)

        return attachment_info
