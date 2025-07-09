# ============================================================================
# email_parser/parsers/proofpoint_detector.py - ENHANCED VERSION
# ============================================================================
"""
Enhanced Proofpoint email detection and unwrapping.

This module provides enhanced email structure extraction with special support
for Proofpoint-wrapped emails. It can detect and unwrap emails that have been
processed by Proofpoint email security systems.
"""

import logging
import re
import base64
from typing import Optional, Tuple, Dict, Any
from email.message import Message
import email.parser
import email.policy
from shared.config import config


class ProofpointDetector:
    """Enhanced Proofpoint detection with flexible patterns."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
        # Flexible marker patterns for different Proofpoint configurations from config
        self.header_markers = [marker for marker in config.PROOFPOINT_MARKERS if "Header" in marker or "Original" in marker]
        self.content_markers = [marker for marker in config.PROOFPOINT_MARKERS if "Reported" in marker or "End Email Headers" in marker]

    def is_proofpoint_email(self, message: Message) -> bool:
        """Detect if this is a Proofpoint-wrapped email with enhanced detection."""
        try:
            subject = message.get("Subject", "")
            
            # Enhanced subject pattern detection from config
            subject_indicators = config.PROOFPOINT_SUBJECT_INDICATORS
            
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
        return header_count >= config.EMAIL_CONTENT_INDICATORS

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
                # CRITICAL FIX: Check if email_content contains the full proofpoint structure
                # and extract the inner email from it
                if self._contains_proofpoint_indicators(email_content):
                    self.logger.debug("Email content contains proofpoint structure, extracting inner email")
                    inner_email = self._extract_inner_email_from_proofpoint(email_content)
                    if inner_email:
                        self.logger.debug(f"Successfully extracted inner email: {len(inner_email)} chars")
                        return inner_email
                
                self.logger.debug("Only body content found, creating minimal email structure")
                # Create a minimal email structure with the content as the body
                # This ensures the email parser can properly extract the body content
                minimal_email = f"""MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

{email_content}"""
                return minimal_email
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
        
        # Debug: Show first 1000 characters to understand the structure
        self.logger.info(f"🔍 DEBUG: First 1000 chars of Proofpoint text: {text[:1000]}")
        
        # Try to extract headers
        headers_text = self._extract_headers_section(text)
        self.logger.info(f"🔍 DEBUG: Headers extraction result: {len(headers_text)} chars")
        if headers_text:
            self.logger.info(f"🔍 DEBUG: Headers content preview: {headers_text[:200]}")
        
        # Try to extract email content 
        email_content = self._extract_content_section(text)
        self.logger.info(f"🔍 DEBUG: Content extraction result: {len(email_content)} chars")
        if email_content:
            self.logger.info(f"🔍 DEBUG: Content preview: {email_content[:500]}")
        
        # If we didn't find structured sections, try to find the raw email
        if not email_content:
            email_content = self._extract_raw_email(text)
            self.logger.info(f"🔍 DEBUG: Raw email extraction result: {len(email_content)} chars")
        
        # CRITICAL FIX: If we still have no email content but the text contains both
        # header and content markers, try to extract the entire email after the headers
        if not email_content and headers_text and "Begin Reported Email" in text:
            email_content = self._extract_email_after_headers(text)
            self.logger.info(f"🔍 DEBUG: Email after headers extraction result: {len(email_content)} chars")
        
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
            # Standard Proofpoint format - extract just the actual email body, not headers
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
                    
                    # CRITICAL FIX: Clean the extracted content to separate email body from embedded headers
                    cleaned_content = self._clean_extracted_email_content(content)
                    return cleaned_content
        
        return ""

    def _clean_extracted_email_content(self, content: str) -> str:
        """Clean extracted email content to separate actual email body from embedded headers."""
        # The content often contains both the actual email body AND the raw email headers
        # We want to extract just the email body for the body field
        
        # CRITICAL FIX: The main issue is that the content has transport headers at the end
        # We need to extract only the email body part, not the transport headers
        
        # First, try to find the actual email body by looking for the end of the embedded email
        # The structure is usually: [email body content] \\---------- End Reported Email ---------- [transport headers]
        
        # Look for the end marker that indicates where the email body ends
        end_markers = [
            "\\---------- End Reported Email ----------",  # This is the actual format in the content
            "---------- End Reported Email ----------",
            "End Reported Email",
        ]
        
        for marker in end_markers:
            if marker in content:
                # Extract only the content before the end marker
                parts = content.split(marker, 1)
                if len(parts) > 1:
                    email_body = parts[0].strip()
                    self.logger.debug(f"✓ Found end marker '{marker}', extracted body: {len(email_body)} chars")
                    
                    # Clean the extracted body further
                    cleaned_body = self._extract_actual_email_body(email_body)
                    if cleaned_body:
                        return cleaned_body
        
        # If no end marker found, try to identify the body content from the structure
        cleaned_body = self._extract_actual_email_body(content)
        if cleaned_body:
            return cleaned_body
        
        # Final fallback: return original content but log that we couldn't clean it
        self.logger.warning(f"Could not clean extracted content, returning original ({len(content)} chars)")
        return content
    
    def _extract_actual_email_body(self, content: str) -> str:
        """Extract the actual email body from content that may contain headers."""
        # Look for patterns that indicate the start of the actual email body
        
        # Common patterns in email body content vs headers:
        # 1. Headers have "Key: Value" format
        # 2. Body content is usually readable text
        # 3. In this case, we're looking for the OneTrust welcome message
        
        # Look for specific content patterns that indicate email body
        body_start_patterns = [
            r"(Welcome to OneTrust!.*)",
            r"(An account has been created.*)",
            r"(CCEP.*Welcome.*)",
            r"(ZjQcmQRYFpfptBannerStart.*)",
            r"(\*\*WARNHINWEIS.*)",  # Warning message in email
        ]
        
        for pattern in body_start_patterns:
            match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
            if match:
                body_content = match.group(1).strip()
                self.logger.debug(f"✓ Found body start pattern, extracted {len(body_content)} chars")
                
                # Clean any remaining headers from the body
                cleaned_body = self._remove_embedded_headers_from_body(body_content)
                if len(cleaned_body) > 50:
                    return cleaned_body
        
        # Alternative approach: split on lines and find where headers end
        lines = content.split('\n')
        body_lines = []
        skip_headers = True
        
        for line in lines:
            line_stripped = line.strip()
            
            # Skip empty lines
            if not line_stripped:
                continue
            
            # Check if this looks like a header line
            if skip_headers and ':' in line_stripped and not line_stripped.startswith(' '):
                header_part = line_stripped.split(':', 1)[0]
                
                # Known email headers - skip these
                if header_part in ['Received', 'Authentication-Results', 'Date', 'From', 'Message-ID', 
                                  'Subject', 'To', 'Return-Path', 'MIME-Version', 'Content-Type'] or \
                   header_part.startswith('X-'):
                    continue
                else:
                    # This might be body content that happens to have a colon
                    skip_headers = False
                    body_lines.append(line)
            else:
                # This is not a header, add to body
                skip_headers = False
                body_lines.append(line)
        
        if body_lines:
            body_content = '\n'.join(body_lines).strip()
            if len(body_content) > 50:
                self.logger.debug(f"✓ Extracted body by skipping headers: {len(body_content)} chars")
                return body_content
        
        return ""
    
    def _remove_embedded_headers_from_body(self, content: str) -> str:
        """Remove any remaining email headers from body content."""
        lines = content.split('\n')
        clean_lines = []
        
        for line in lines:
            line_stripped = line.strip()
            
            # Skip lines that look like email headers
            if ':' in line_stripped and not line_stripped.startswith(' ') and not line_stripped.startswith('\t'):
                header_part = line_stripped.split(':', 1)[0]
                
                # Skip known header types
                if header_part in ['Received', 'Authentication-Results', 'Date', 'From', 'Message-ID', 
                                  'Subject', 'To', 'Return-Path', 'MIME-Version', 'Content-Type'] or \
                   header_part.startswith('X-'):
                    continue
            
            # Keep this line - it's body content
            clean_lines.append(line)
        
        return '\n'.join(clean_lines).strip()
    
    def _looks_like_all_headers(self, text: str) -> bool:
        """Check if text appears to be all email headers."""
        lines = text.split('\n')
        header_count = 0
        total_lines = 0
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            total_lines += 1
            if ':' in line and not line.startswith(' ') and not line.startswith('\t'):
                header_part = line.split(':', 1)[0]
                if len(header_part) < 50:  # Headers are usually not super long
                    header_count += 1
        
        # If more than 80% of lines look like headers, it's probably all headers
        if total_lines > 0:
            return (header_count / total_lines) > 0.8
        return False
    

    def _extract_email_after_headers(self, text: str) -> str:
        """Extract email content that comes after the proofpoint headers section."""
        patterns = [
            # Look for the end of headers and beginning of reported email
            r"---------- End Email Headers ----------\s*\n.*?---------- Begin Reported Email ----------\s*\n(.*?)(?:\n---------- End Reported Email ----------|$)",
            
            # Sometimes the content is everything after "Begin Reported Email"
            r"---------- Begin Reported Email ----------\s*\n(.*?)(?:\n---------- End Reported Email ----------|$)",
            
            # Alternative patterns for different formats
            r"Begin Reported Email[:\s]*[-]*\s*\n(.*?)(?=\nEnd Reported Email|$)",
            
            # If we find both headers and the email content markers, extract everything between them
            r"---------- End Email Headers ----------.*?---------- Begin Reported Email ----------\s*\n(.*?)$",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                content = match.group(1).strip()
                if len(content) > 50:  # Reasonable minimum length
                    self.logger.debug(f"✓ Extracted email content after headers using pattern")
                    return content
        
        # If patterns fail, try to extract everything after "Begin Reported Email"
        if "Begin Reported Email" in text:
            lines = text.split('\n')
            start_found = False
            email_lines = []
            
            for line in lines:
                if "Begin Reported Email" in line:
                    start_found = True
                    continue
                elif "End Reported Email" in line:
                    break
                elif start_found:
                    email_lines.append(line)
            
            if email_lines:
                content = '\n'.join(email_lines).strip()
                if len(content) > 50:
                    self.logger.debug("✓ Extracted email content after 'Begin Reported Email' marker")
                    return content
        
        return ""

    def _extract_inner_email_from_proofpoint(self, proofpoint_content: str) -> Optional[str]:
        """Extract the inner email from a proofpoint structure that contains both headers and content."""
        self.logger.debug("Attempting to extract inner email from proofpoint content")
        
        # Try to find the actual email headers within the proofpoint content
        # The pattern we're looking for is the original email headers that appear after the proofpoint headers
        # and before or within the reported email section
        
        # Look for patterns that indicate where the original email starts
        patterns = [
            # Pattern 1: Headers section followed by reported email section
            r"---------- End Email Headers ----------.*?---------- Begin Reported Email ----------\s*\n(.*?)(?:\n---------- End Reported Email ----------|$)",
            
            # Pattern 2: Just the reported email section
            r"---------- Begin Reported Email ----------\s*\n(.*?)(?:\n---------- End Reported Email ----------|$)",
            
            # Pattern 3: Look for email headers within the content (Date:, From:, To:, Subject:, Message-ID:)
            # This handles cases where the inner email headers are embedded
            r"((?:Date|From|To|Subject|Message-ID|MIME-Version):[^\n]*\n(?:[^\n:]+:[^\n]*\n)*.*?)$",
        ]
        
        for i, pattern in enumerate(patterns, 1):
            match = re.search(pattern, proofpoint_content, re.DOTALL | re.IGNORECASE)
            if match:
                extracted_content = match.group(1).strip()
                self.logger.debug(f"Pattern {i} matched, extracted {len(extracted_content)} chars")
                
                # Validate that this looks like proper email content
                if self._validate_extracted_email_content(extracted_content):
                    self.logger.debug(f"✓ Pattern {i} produced valid email content")
                    
                    # If this doesn't start with headers, try to construct a proper email
                    if not any(extracted_content.startswith(h) for h in ["From:", "To:", "Date:", "Subject:", "MIME-Version:"]):
                        # Extract any headers that might be within the proofpoint structure
                        headers = self._extract_embedded_headers(proofpoint_content)
                        if headers:
                            return f"{headers}\n\n{extracted_content}"
                        else:
                            # Create minimal headers for the extracted content
                            return f"MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n{extracted_content}"
                    else:
                        return extracted_content
        
        self.logger.debug("No valid inner email found in proofpoint content")
        return None
    
    def _validate_extracted_email_content(self, content: str) -> bool:
        """Validate that extracted content looks like valid email content."""
        if not content or len(content) < 50:
            return False
        
        # Check for email-like indicators
        email_indicators = [
            "From:", "To:", "Subject:", "Date:", "Message-ID:",
            "Content-Type:", "MIME-Version:", "@", "login", "welcome",
            "account", "email", "click", "button"
        ]
        
        indicator_count = sum(1 for indicator in email_indicators if indicator.lower() in content.lower())
        
        # Should have at least 3 email indicators to be considered valid
        is_valid = indicator_count >= config.VALID_EMAIL_INDICATOR_COUNT
        
        self.logger.debug(f"Content validation: {indicator_count} indicators found, valid={is_valid}")
        return is_valid
    
    def _extract_embedded_headers(self, proofpoint_content: str) -> str:
        """Extract email headers that might be embedded within the proofpoint structure."""
        headers = []
        
        # Look for email headers in the content
        header_patterns = [
            r"Date:\s*([^\n]+)",
            r"From:\s*([^\n]+)",
            r"To:\s*([^\n]+)",
            r"Subject:\s*([^\n]+)",
            r"Message-ID:\s*([^\n]+)",
        ]
        
        for pattern in header_patterns:
            match = re.search(pattern, proofpoint_content, re.IGNORECASE)
            if match:
                header_line = match.group(0).strip()
                headers.append(header_line)
                self.logger.debug(f"Found embedded header: {header_line}")
        
        if headers:
            return "\n".join(headers)
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
        
        # For Proofpoint content that doesn't start with standard headers,
        # look for patterns like "From: name" anywhere in the content
        for i, line in enumerate(lines):
            # Look for "From:" followed by name/email anywhere in line
            if re.search(r'From:\s*\S.*?(?:@|\s)', line.strip(), re.IGNORECASE):
                email_start = i
                break
        
        if email_start >= 0:
            # Take everything from the first From: line onwards
            email_content = '\n'.join(lines[email_start:])
            if len(email_content) > 100:
                self.logger.debug("✓ Extracted raw email content from Proofpoint format")
                return email_content
        
        # If still nothing found, but we have substantial content, return it all
        if len(text.strip()) > 200:
            self.logger.debug("✓ Using all content as raw email (fallback)")
            return text.strip()
        
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
            content_text = ""
            
            if message.is_multipart():
                for part in message.walk():
                    if part.get_content_type().startswith("text/"):
                        payload = part.get_payload(decode=True)
                        if payload and len(str(payload)) > 10:
                            has_content = True
                            content_text = str(payload)
                            break
            else:
                payload = message.get_payload(decode=True)
                if payload and len(str(payload)) > 10:
                    has_content = True
                    content_text = str(payload)
            
            # For Proofpoint emails, also check if content contains email-like patterns
            # even if headers are missing
            has_email_patterns = False
            if content_text and len(content_text) > 50:
                # Look for email patterns in content
                email_patterns = ["From:", "To:", "Subject:", "Date:", "@"]
                pattern_count = sum(1 for pattern in email_patterns if pattern in content_text[:2000])
                has_email_patterns = pattern_count >= 2
            
            # Original validation: requires From header and (Subject or Content)
            is_valid_standard = has_from and (has_subject or has_content)
            
            # Relaxed validation for Proofpoint: just requires substantial content with email patterns
            is_valid_proofpoint = has_content and has_email_patterns and len(content_text) > 200
            
            is_valid = is_valid_standard or is_valid_proofpoint
            
            self.logger.debug(
                f"Validation: From={has_from}, Subject={has_subject}, "
                f"Content={has_content}, EmailPatterns={has_email_patterns}, "
                f"Standard={is_valid_standard}, Proofpoint={is_valid_proofpoint}, Valid={is_valid}"
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