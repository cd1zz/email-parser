# ============================================================================
# email_parser/parsers/proofpoint_detector.py - ENHANCED VERSION
# ============================================================================
"""Enhanced Proofpoint email detection with flexible patterns."""

import logging
import re
import base64
from typing import Optional, Tuple, Dict, Any
from email.message import Message
import email.parser
import email.policy


class ProofpointDetector:
    """Enhanced Proofpoint detection with flexible patterns."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
        # Flexible marker patterns for different Proofpoint configurations
        self.header_markers = [
            "---------- Begin Email Headers ----------",
            "Begin Email Headers",
            "Email Headers:",
            "Original Message Headers",
            "-----Original Message-----",
        ]
        
        self.content_markers = [
            "---------- Begin Reported Email ----------", 
            "---------- Begin Email ----------",
            "Begin Reported Email",
            "Reported Email:",
            "Original Message:",
            "---------- End Email Headers ----------",
        ]

    def is_proofpoint_email(self, message: Message) -> bool:
        """Detect if this is a Proofpoint-wrapped email with enhanced detection."""
        try:
            subject = message.get("Subject", "")
            
            # Enhanced subject pattern detection
            subject_indicators = [
                "Potential Phish:",
                "Suspicious Email:",
                "Phishing Alert:",
                "Security Alert:",
                "Proofpoint",  # Added: catch test emails with "Proofpoint" in subject
                "[ALERT]",
                "[WARNING]",
                "Email Security",
            ]
            
            has_subject_indicator = any(indicator.lower() in subject.lower() for indicator in subject_indicators)
            
            # Get body content for marker detection
            body_content = self._extract_all_content(message)
            if not body_content:
                self.logger.debug("No body content found for Proofpoint detection")
                return False
            
            # Check for Proofpoint markers in content
            has_markers = self._check_for_proofpoint_markers(body_content)
            
            # Enhanced detection logic:
            # 1. Subject indicator + body markers = Proofpoint (high confidence)
            # 2. Strong body markers without subject = Proofpoint (medium confidence) 
            # 3. Subject indicator without markers = not Proofpoint
            
            if has_subject_indicator and has_markers:
                self.logger.info(f"✓ Detected Proofpoint email (subject + markers): {subject}")
                return True
            elif has_markers and self._has_strong_proofpoint_indicators(body_content):
                self.logger.info(f"✓ Detected Proofpoint email (strong markers): {subject}")
                return True
            elif has_subject_indicator:
                self.logger.debug(f"Subject indicates Proofpoint but no body markers found: {subject}")
                return False
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Error detecting Proofpoint email: {e}")
            return False

    def _check_for_proofpoint_markers(self, content: str) -> bool:
        """Check for any Proofpoint markers in content."""
        all_markers = self.header_markers + self.content_markers
        found_markers = [marker for marker in all_markers if marker in content]
        
        if found_markers:
            self.logger.debug(f"Found Proofpoint markers: {found_markers}")
            return True
        return False

    def _has_strong_proofpoint_indicators(self, content: str) -> bool:
        """Check for strong Proofpoint indicators that don't require subject matching."""
        strong_indicators = [
            "---------- Begin Email Headers ----------",
            "---------- Begin Reported Email ----------",
            "---------- End Email Headers ----------",
        ]
        
        strong_count = sum(1 for indicator in strong_indicators if indicator in content)
        
        # Require at least 2 strong indicators for subject-less detection
        if strong_count >= 2:
            self.logger.debug(f"Found {strong_count} strong Proofpoint indicators")
            return True
        
        return False

    def extract_wrapped_email(self, message: Message) -> Optional[Message]:
        """Extract the wrapped email from Proofpoint container."""
        try:
            self.logger.info("Extracting wrapped email from Proofpoint container")
            
            # Get all content including base64
            full_content = self._extract_all_content(message)
            if not full_content:
                self.logger.warning("No content found in Proofpoint email")
                return None
            
            self.logger.debug(f"Analyzing {len(full_content)} characters for Proofpoint sections")
            
            # Extract sections with enhanced patterns
            headers_text, email_content = self._extract_sections(full_content)
            
            if not headers_text and not email_content:
                self.logger.warning("Could not extract any Proofpoint sections")
                # Try alternative extraction methods
                return self._try_alternative_extraction(full_content)
            
            # Reconstruct email
            reconstructed = self._reconstruct_email(headers_text, email_content)
            if not reconstructed:
                return None
            
            # Parse reconstructed email
            parser = email.parser.Parser(policy=email.policy.default)
            unwrapped_message = parser.parsestr(reconstructed)
            
            # Validate the unwrapped message
            if self._validate_unwrapped_email(unwrapped_message):
                self.logger.info("✅ Successfully unwrapped Proofpoint email")
                return unwrapped_message
            else:
                self.logger.warning("Unwrapped email failed validation")
                return None
                
        except Exception as e:
            self.logger.error(f"Error extracting Proofpoint content: {e}")
            return None

    def _try_alternative_extraction(self, content: str) -> Optional[Message]:
        """Try alternative extraction methods when standard patterns fail."""
        self.logger.info("Trying alternative Proofpoint extraction methods")
        
        # Look for forwarded email patterns (common in forwarded Proofpoint emails)
        forwarded_patterns = [
            r"From:.*?\r?\nSent:.*?\r?\nTo:.*?\r?\nSubject:.*?\r?\n\r?\n(.*)",
            r"-----Original Message-----\r?\n(.*)",
            r"From:.*?Subject:.*?\r?\n\r?\n(.*)",
        ]
        
        for pattern in forwarded_patterns:
            match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
            if match:
                potential_email = match.group(1).strip()
                if len(potential_email) > 200 and self._looks_like_email_content(potential_email):
                    self.logger.info("✓ Found email content using forwarded pattern")
                    try:
                        parser = email.parser.Parser(policy=email.policy.default)
                        # Try to parse as-is first
                        test_message = parser.parsestr(potential_email)
                        if self._validate_unwrapped_email(test_message):
                            return test_message
                    except Exception:
                        pass
        
        return None

    def _looks_like_email_content(self, content: str) -> bool:
        """Check if content looks like email content."""
        email_indicators = ["From:", "To:", "Subject:", "Date:", "Content-Type:", "@"]
        header_count = sum(1 for indicator in email_indicators if indicator in content[:1000])
        return header_count >= 3

    def _reconstruct_email(self, headers_text: str, email_content: str) -> Optional[str]:
        """Reconstruct email from headers and content."""
        if headers_text and email_content:
            reconstructed = f"{headers_text}\n\n{email_content}"
            self.logger.debug(f"Reconstructed email: {len(reconstructed)} characters")
            return reconstructed
        elif email_content:
            # Sometimes we only get the email content without separate headers
            # Check if the content already contains headers
            if any(email_content.startswith(header) for header in ["From:", "To:", "Subject:", "Date:"]):
                self.logger.debug("Email content already contains headers")
                return email_content
            else:
                self.logger.debug("Only body content found, no headers")
                return email_content
        else:
            self.logger.warning("No email content found for reconstruction")
            return None

    def _extract_all_content(self, message: Message) -> str:
        """Extract all text content including base64-decoded parts."""
        all_content = []
        
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                content = self._extract_part_content(part)
                if content:
                    all_content.append(content)
        else:
            content = self._extract_part_content(message)
            if content:
                all_content.append(content)
        
        return "\n".join(all_content)

    def _extract_part_content(self, part: Message) -> Optional[str]:
        """Extract content from a single part with robust base64 handling."""
        try:
            encoding = part.get("Content-Transfer-Encoding", "").lower().strip()
            
            # Special handling for base64 (critical for Proofpoint)
            if encoding == "base64":
                return self._decode_base64_content(part)
            
            # Standard decoding for other encodings
            payload = part.get_payload(decode=True)
            if not payload:
                return None
                
            if isinstance(payload, bytes):
                charset = part.get_content_charset() or "utf-8"
                try:
                    return payload.decode(charset, errors="ignore")
                except (UnicodeDecodeError, LookupError):
                    # Try common fallbacks
                    for fallback in ["utf-8", "windows-1252", "latin-1"]:
                        try:
                            return payload.decode(fallback, errors="ignore")
                        except (UnicodeDecodeError, LookupError):
                            continue
                    return payload.decode("utf-8", errors="replace")
            
            return str(payload) if payload else None
            
        except Exception as e:
            self.logger.debug(f"Error extracting part content: {e}")
            return None

    def _decode_base64_content(self, part: Message) -> Optional[str]:
        """Robust base64 content decoding."""
        try:
            raw_payload = part.get_payload(decode=False)
            if not isinstance(raw_payload, str):
                return None
            
            # Clean base64 string
            clean_b64 = re.sub(r'\s+', '', raw_payload.strip())
            if not clean_b64:
                return None
            
            # Decode base64
            try:
                decoded_bytes = base64.b64decode(clean_b64)
            except Exception as e:
                self.logger.debug(f"Base64 decode failed: {e}")
                return None
            
            # Try different charsets
            for charset in ["utf-8", "windows-1252", "latin-1"]:
                try:
                    decoded_text = decoded_bytes.decode(charset, errors="ignore")
                    
                    # Check if this looks like Proofpoint content
                    if self._contains_proofpoint_indicators(decoded_text):
                        self.logger.info(f"✓ Found Proofpoint content in base64 using {charset}")
                        return decoded_text
                        
                    # Even if no markers, return if it's substantial text content
                    if len(decoded_text.strip()) > 100:
                        return decoded_text
                        
                except UnicodeDecodeError:
                    continue
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error decoding base64 content: {e}")
            return None

    def _contains_proofpoint_indicators(self, text: str) -> bool:
        """Check if text contains Proofpoint indicators."""
        indicators = (
            self.header_markers + 
            self.content_markers + 
            ["Potential Phish:", "Security Alert:", "Suspicious Email:"]
        )
        return any(indicator in text for indicator in indicators)

    def _extract_sections(self, text: str) -> Tuple[str, str]:
        """Extract headers and content sections from Proofpoint text."""
        headers_text = ""
        email_content = ""
        
        self.logger.debug(f"Extracting sections from {len(text)} characters")
        
        # Try to extract headers
        headers_text = self._extract_headers_section(text)
        
        # Try to extract email content 
        email_content = self._extract_content_section(text)
        
        # If we didn't find structured sections, try to find the raw email
        if not email_content:
            email_content = self._extract_raw_email(text)
        
        self.logger.info(
            f"Section extraction: headers={len(headers_text)} chars, "
            f"content={len(email_content)} chars"
        )
        
        return headers_text, email_content

    def _extract_headers_section(self, text: str) -> str:
        """Extract headers section using flexible patterns."""
        patterns = [
            # Standard Proofpoint format
            r"---------- Begin Email Headers ----------\s*\n(.*?)\n---------- End Email Headers ----------",
            
            # Variations with different dash counts
            r"[-]{5,20} Begin Email Headers [-]{0,20}\s*\n(.*?)\n[-]{5,20} End Email Headers [-]{0,20}",
            
            # Without end markers
            r"---------- Begin Email Headers ----------\s*\n(.*?)(?=\n---------- Begin|$)",
            
            # Simplified patterns
            r"Begin Email Headers[:\s]*[-]*\s*\n(.*?)(?=\nEnd Email Headers|\nBegin|$)",
            
            # Headers section patterns
            r"Email Headers:\s*\n(.*?)(?=\n(?:Reported Email|Begin|------|$))",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                headers = match.group(1).strip()
                if self._validate_headers(headers):
                    self.logger.debug(f"✓ Extracted headers using pattern")
                    return headers
        
        return ""

    def _extract_content_section(self, text: str) -> str:
        """Extract email content section using flexible patterns."""
        patterns = [
            # Standard Proofpoint format
            r"---------- Begin Reported Email ----------\s*\n(.*?)(?:\n---------- End Reported Email ----------|$)",
            
            # Variations
            r"[-]{5,20} Begin Reported Email [-]{0,20}\s*\n(.*?)(?:\n[-]{5,20} End Reported Email [-]{0,20}|$)",
            
            r"---------- Begin Email ----------\s*\n(.*?)(?:\n---------- End Email ----------|$)",
            
            # Simplified patterns
            r"Begin Reported Email[:\s]*[-]*\s*\n(.*?)(?=\nEnd Reported Email|$)",
            
            r"Reported Email:\s*\n(.*?)(?=\n(?:---|$))",
            
            # Sometimes the entire content after headers is the email
            r"Original Message:\s*\n(.*?)$",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                content = match.group(1).strip()
                if len(content) > 50:  # Reasonable minimum length
                    self.logger.debug(f"✓ Extracted content using pattern")
                    return content
        
        return ""

    def _extract_raw_email(self, text: str) -> str:
        """Extract raw email if no structured markers found."""
        # Look for email header patterns in the text
        lines = text.split('\n')
        email_start = -1
        
        for i, line in enumerate(lines):
            # Look for typical email headers
            if re.match(r'^(From|To|Subject|Date|Message-ID):\s*\S', line.strip()):
                email_start = i
                break
        
        if email_start >= 0:
            # Take everything from the first header onwards
            email_content = '\n'.join(lines[email_start:])
            if len(email_content) > 100:
                self.logger.debug("✓ Extracted raw email content")
                return email_content
        
        return ""

    def _validate_headers(self, headers: str) -> bool:
        """Validate that extracted text looks like email headers."""
        if not headers or len(headers) < 20:
            return False
        
        # Check for typical email headers
        header_patterns = [
            r'^From:\s*\S',
            r'^To:\s*\S', 
            r'^Subject:\s*\S',
            r'^Date:\s*\S',
        ]
        
        header_count = 0
        for pattern in header_patterns:
            if re.search(pattern, headers, re.MULTILINE | re.IGNORECASE):
                header_count += 1
        
        return header_count >= 2

    def _validate_unwrapped_email(self, message: Message) -> bool:
        """Validate that unwrapped message is a proper email."""
        try:
            # Check for essential headers
            has_from = bool(message.get("From"))
            has_subject = bool(message.get("Subject")) 
            
            # Check for some content
            has_content = False
            if message.is_multipart():
                for part in message.walk():
                    if part.get_content_type().startswith("text/"):
                        payload = part.get_payload(decode=True)
                        if payload and len(str(payload)) > 10:
                            has_content = True
                            break
            else:
                payload = message.get_payload(decode=True)
                if payload and len(str(payload)) > 10:
                    has_content = True
            
            is_valid = has_from and (has_subject or has_content)
            
            self.logger.debug(
                f"Validation: From={has_from}, Subject={has_subject}, "
                f"Content={has_content}, Valid={is_valid}"
            )
            
            return is_valid
            
        except Exception as e:
            self.logger.debug(f"Validation error: {e}")
            return False


class EnhancedEmailStructureExtractor:
    """Wrapper that adds Proofpoint detection to EmailStructureExtractor."""

    def __init__(self, original_extractor, logger: logging.Logger):
        self.original_extractor = original_extractor
        self.logger = logger
        self.proofpoint_detector = ProofpointDetector(logger)

    def extract_structure(self, message: Message, depth: int = 0, verbose: bool = False) -> Dict[str, Any]:
        """Enhanced structure extraction with Proofpoint unwrapping."""
        
        # Only check for Proofpoint at the root level
        if depth == 0:
            self.logger.debug("Checking for Proofpoint email at root level")
            
            if self.proofpoint_detector.is_proofpoint_email(message):
                self.logger.info("🔍 Processing Proofpoint-wrapped email")
                
                unwrapped_message = self.proofpoint_detector.extract_wrapped_email(message)
                
                if unwrapped_message:
                    self.logger.info("✅ Successfully unwrapped Proofpoint email")
                    
                    # Process the unwrapped email
                    structure = self.original_extractor.extract_structure(
                        unwrapped_message, depth, verbose
                    )
                    
                    # Add Proofpoint metadata
                    self._add_proofpoint_metadata(structure, message, True, verbose)
                    return structure
                else:
                    self.logger.warning("❌ Failed to unwrap Proofpoint email")
                    
                    # Process as regular email but mark as failed unwrapping
                    structure = self.original_extractor.extract_structure(
                        message, depth, verbose
                    )
                    self._add_proofpoint_metadata(structure, message, False, verbose)
                    return structure
            else:
                self.logger.debug("No Proofpoint email detected")
        
        # Regular processing for non-Proofpoint emails
        return self.original_extractor.extract_structure(message, depth, verbose)

    def _add_proofpoint_metadata(self, structure: Dict[str, Any], original_message: Message, 
                                success: bool, verbose: bool) -> None:
        """Add Proofpoint metadata to structure."""
        proofpoint_info = {
            "is_proofpoint_wrapped": True,
            "extraction_successful": success,
            "original_subject": original_message.get("Subject", ""),
        }
        
        if verbose:
            structure["proofpoint_info"] = proofpoint_info
        else:
            # Add to metadata section for streamlined format
            if "metadata" not in structure:
                structure["metadata"] = {}
            structure["metadata"].update({
                "proofpoint_wrapped": True,
                "proofpoint_extraction_successful": success,
                "original_proofpoint_subject": original_message.get("Subject", ""),
            })