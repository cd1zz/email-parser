# ============================================================================
# email_parser/structure_extractor.py - Enhanced with document processing
# ============================================================================

import email
import base64
import quopri
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

    def extract_structure(self, message: Message, depth: int = 0, verbose: bool = False) -> Dict[str, Any]:
        """Extract email structure with streamlined default output."""
        self.logger.info(f"Extracting email structure at depth {depth}, verbose={verbose}")
        
        if verbose:
            return self._extract_verbose_structure(message, depth)
        else:
            return self._extract_streamlined_structure(message, depth)

    def _extract_streamlined_structure(self, message: Message, depth: int = 0) -> Dict[str, Any]:
        """Extract streamlined email structure with document processing."""
        self.logger.info(f"Extracting streamlined structure at depth {depth}")
        
        # Build streamlined structure
        if depth == 0:
            # Root level includes metadata and summary
            structure = {
                'metadata': self._build_metadata(message),
                'email': self._build_streamlined_email(message, depth),
                'summary': None,  # Will be populated after processing
                'document_analysis': {
                    'total_documents_processed': 0,
                    'total_text_extracted': 0,
                    'document_urls_found': 0,
                    'extraction_errors': []
                }
            }
            
            # Process all documents and collect results if enabled
            if self.enable_document_processing:
                doc_analysis = self._process_all_documents(structure['email'])
                structure['document_analysis'] = doc_analysis
            
            # Generate summary after email and document processing
            structure['summary'] = self._generate_summary(
                structure['email'],
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
            'level': depth,
            'headers': self._extract_streamlined_headers(message),
            'body': self._extract_streamlined_body(message),
            'attachments': [],
            'nested_emails': [],
            'urls': [],
            'document_extracts': []  # New: Store extracted document text
        }
        
        # Process attachments and nested emails
        attachments, nested_emails = self._process_attachments_streamlined(message, depth)
        email_obj['attachments'] = attachments
        email_obj['nested_emails'] = nested_emails
        
        self.logger.info(f"Built email at depth {depth}: {len(attachments)} attachments, {len(nested_emails)} nested emails")
        
        # Extract URLs if analyzer available and at root level
        if self.url_analyzer and depth == 0:
            email_obj['urls'] = self._extract_urls_streamlined(email_obj)
        
        return email_obj

    def _build_streamlined_attachment(self, part: Message, depth: int) -> Dict[str, Any]:
        """Build streamlined attachment info with document text extraction."""
        
        # Enhanced filename extraction
        filename = self._extract_attachment_filename(part)
        
        content_type = part.get_content_type()
        
        attachment = {
            'name': filename,
            'type': 'other',  # Will be updated after content analysis
            'size': None,
            'mime_type': content_type,
            'is_inline': 'inline' in part.get('Content-Disposition', '').lower(),
            'contains_email': False,
            'document_text': None,  # New: Extracted document text
            'document_urls': [],    # New: URLs found in document
            'extraction_info': None  # New: Document extraction metadata
        }
        
        # Get size and analyze content
        try:
            # Handle message/rfc822 differently - don't decode!
            if content_type == 'message/rfc822':
                # For RFC822 messages, the payload is the nested message object
                payload = part.get_payload()  # Don't decode!
                if isinstance(payload, list) and len(payload) > 0:
                    # Size estimation for RFC822 (convert back to string)
                    attachment['size'] = len(str(payload[0])) if payload[0] else 0
                else:
                    attachment['size'] = 0
            else:
                payload = part.get_payload(decode=True)
                if payload:
                    attachment['size'] = len(payload)
                    
                    # Content analysis for hash and type detection
                    analysis = self.content_analyzer.analyze_content(payload, filename, content_type)
                    attachment['hash_md5'] = analysis.hashes.get('md5', '')
                    
                    # Use fingerprinted content type if more confident
                    final_content_type = content_type
                    if analysis.detected_type and analysis.confidence > 0.7:
                        final_content_type = analysis.mime_type
                        self.logger.debug(f"Using fingerprinted content type: {final_content_type}")
                    
                    # Categorize based on final content type
                    attachment['type'] = self._categorize_attachment_type(final_content_type, filename)
                    
                    # NEW: Process document attachments for text extraction
                    if (
                        self.enable_document_processing
                        and self._is_document_type(final_content_type, filename)
                    ):
                        self._process_document_attachment(
                            attachment, payload, filename, final_content_type
                        )
            
            # Check for nested email (this should work for message/rfc822 now)
            if self._detect_nested_email(part):
                attachment['contains_email'] = True
                # Set type to email if it contains an email
                attachment['type'] = 'email'
                    
        except Exception as e:
            self.logger.debug(f"Error analyzing attachment: {e}")
        
        return attachment

    def _is_document_type(self, content_type: str, filename: str = None) -> bool:
        """Check if attachment is a document type we can extract text from."""
        document_types = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        ]
        
        # Check content type
        if content_type in document_types:
            return True
        
        # Check filename extension as fallback
        if filename:
            filename_lower = filename.lower()
            document_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx']
            return any(filename_lower.endswith(ext) for ext in document_extensions)
        
        return False

    def _process_document_attachment(self, attachment: Dict[str, Any], payload: bytes,
                                   filename: str, content_type: str) -> None:
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
            attachment['extraction_info'] = doc_result['extraction_result']
            
            if doc_result['processing_success']:
                # Store extracted text (truncated for main attachment info)
                extracted_text = doc_result['extracted_text']
                if extracted_text:
                    # Store truncated version in attachment
                    if len(extracted_text) > 500:
                        attachment['document_text'] = extracted_text[:500] + "... [TRUNCATED]"
                    else:
                        attachment['document_text'] = extracted_text
                    
                    # Store URLs found in document
                    attachment['document_urls'] = doc_result['urls_found']
                    
                    # Update attachment type to 'document' if successfully processed
                    if attachment['type'] == 'other':
                        attachment['type'] = 'document'
                    
                    self.logger.info(f"Successfully extracted {len(extracted_text)} characters "
                                   f"and {len(doc_result['urls_found'])} URLs from {filename}")
            else:
                self.logger.warning(f"Failed to extract text from document {filename}: "
                                  f"{doc_result['extraction_result'].get('error_message', 'Unknown error')}")
                
        except Exception as e:
            self.logger.error(f"Error processing document attachment {filename}: {e}")
            attachment['extraction_info'] = {
                'success': False,
                'error_message': f"Processing failed: {str(e)}"
            }

    def _process_all_documents(self, email_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Process all document attachments in the email structure and collect analysis."""
        if not self.enable_document_processing:
            return {
                'total_documents_processed': 0,
                'total_text_extracted': 0,
                'document_urls_found': 0,
                'extraction_errors': [],
                'document_types_found': [],
                'successful_extractions': [],
                'failed_extractions': []
            }
        analysis = {
            'total_documents_processed': 0,
            'total_text_extracted': 0,
            'document_urls_found': 0,
            'extraction_errors': [],
            'document_types_found': set(),
            'successful_extractions': [],
            'failed_extractions': []
        }
        
        def process_email_documents(email_data: Dict[str, Any]):
            """Recursively process documents in email and nested emails."""
            
            # Process attachments in current email
            for attachment in email_data.get('attachments', []):
                if attachment.get('extraction_info'):
                    analysis['total_documents_processed'] += 1
                    
                    extraction_info = attachment['extraction_info']
                    if extraction_info.get('success'):
                        analysis['successful_extractions'].append({
                            'filename': attachment.get('name'),
                            'document_type': extraction_info.get('document_type'),
                            'extraction_method': extraction_info.get('extraction_method'),
                            'text_length': extraction_info.get('metadata', {}).get('character_count', 0),
                            'urls_found': len(attachment.get('document_urls', []))
                        })
                        
                        # Add to totals
                        text_length = extraction_info.get('metadata', {}).get('character_count', 0)
                        analysis['total_text_extracted'] += text_length
                        analysis['document_urls_found'] += len(attachment.get('document_urls', []))
                        
                        # Track document types
                        doc_type = extraction_info.get('document_type')
                        if doc_type:
                            analysis['document_types_found'].add(doc_type)
                    else:
                        analysis['failed_extractions'].append({
                            'filename': attachment.get('name'),
                            'error': extraction_info.get('error_message', 'Unknown error')
                        })
                        analysis['extraction_errors'].append(
                            f"{attachment.get('name', 'unknown')}: {extraction_info.get('error_message', 'Unknown error')}"
                        )
            
            # Process nested emails recursively
            for nested_email in email_data.get('nested_emails', []):
                process_email_documents(nested_email)
        
        # Start processing from root email
        process_email_documents(email_obj)
        
        # Convert set to list for JSON serialization
        analysis['document_types_found'] = list(analysis['document_types_found'])
        
        self.logger.info(f"Document analysis complete: {analysis['total_documents_processed']} processed, "
                        f"{len(analysis['successful_extractions'])} successful, "
                        f"{analysis['total_text_extracted']} characters extracted")
        
        return analysis

    def _extract_urls_streamlined(self, email_obj: Dict[str, Any]) -> List[str]:
        """Extract URLs for streamlined format including document URLs."""
        all_urls = []
        
        try:
            if self.url_analyzer:
                # Create temporary structure for URL analysis
                temp_structure = {
                    'body': email_obj['body'],
                    'headers': email_obj['headers'],
                    'attachments': email_obj['attachments'],
                    'nested_emails': email_obj['nested_emails']
                }
                
                analysis = self.url_analyzer.analyze_email_urls(temp_structure)
                all_urls.extend(analysis.final_urls)
                
                # Add URLs from document extracts if processing enabled
                if self.enable_document_processing:
                    def collect_document_urls(email_data):
                        for attachment in email_data.get('attachments', []):
                            doc_urls = attachment.get('document_urls', [])
                            all_urls.extend(doc_urls)

                        for nested_email in email_data.get('nested_emails', []):
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

    def _generate_summary(self, email_obj: Dict[str, Any], doc_analysis: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate summary section including document analysis."""
        def collect_emails(email, emails_list, subjects_list, timeline_list, forwarding_chain):
            """Recursively collect email info."""
            emails_list.append(email)
            self.logger.debug(f"Collected email at level {email.get('level', 'unknown')}: {email.get('headers', {}).get('subject', 'No subject')}")
            
            if email.get('headers', {}).get('subject'):
                subjects_list.append(email['headers']['subject'])
            
            if email.get('headers', {}).get('date'):
                timeline_list.append(email['headers']['date'])
            
            # Build forwarding chain
            from_addr = email.get('headers', {}).get('from', '')
            to_addr = email.get('headers', {}).get('to', '')
            if from_addr and to_addr:
                forwarding_chain.append(f"{from_addr} → {to_addr}")
            
            # Process nested emails recursively
            for nested in email.get('nested_emails', []):
                self.logger.debug(f"Processing nested email from level {email.get('level', 'unknown')}")
                collect_emails(nested, emails_list, subjects_list, timeline_list, forwarding_chain)
        
        all_emails = []
        all_subjects = []
        all_timeline = []
        forwarding_chain = []
        
        self.logger.info("Starting email collection for summary")
        collect_emails(email_obj, all_emails, all_subjects, all_timeline, forwarding_chain)
        self.logger.info(f"Collected {len(all_emails)} total emails for summary")
        
        # Collect domains
        domains = set()
        for email_entry in all_emails:
            for header in ['from', 'to', 'cc']:
                value = email_entry.get('headers', {}).get(header, '')
                if '@' in value:
                    try:
                        # Extract domain from email address - handle different formats
                        if '<' in value and '>' in value:
                            # Extract from "Name <email@domain.com>" format
                            email_part = value.split('<')[1].split('>')[0]
                        else:
                            # Direct email format
                            email_part = value
                        
                        if '@' in email_part:
                            domain = email_part.split('@')[1].strip()
                            if domain:
                                domains.add(domain)
                    except Exception:
                        pass
        
        # Collect attachment types from all emails
        attachment_types = set()
        total_attachments = 0
        for email_entry in all_emails:
            for att in email_entry.get('attachments', []):
                attachment_types.add(att.get('type', 'unknown'))
                total_attachments += 1
        
        # Build summary with document analysis
        summary = {
            'email_chain_length': len(all_emails),
            'attachment_types': sorted(list(attachment_types)),
            'domains_involved': sorted(list(domains)),
            'key_subjects': all_subjects,
            'timeline': sorted(set(all_timeline)),
            'forwarding_chain': forwarding_chain,
            'contains_external_domains': len(domains) > 1,
            'has_suspicious_subject_patterns': any(
                keyword in ' '.join(all_subjects).lower() 
                for keyword in ['urgent', 'action required', 'expires', 'click here', 'verify', 'authentication expires']
            ),
            'authentication_results': self._extract_auth_results(email_obj),
            'total_attachments': total_attachments
        }
        
        # Add document analysis to summary if available
        if doc_analysis:
            summary['document_summary'] = {
                'total_documents_processed': doc_analysis['total_documents_processed'],
                'successful_extractions': len(doc_analysis['successful_extractions']),
                'failed_extractions': len(doc_analysis['failed_extractions']),
                'total_text_extracted': doc_analysis['total_text_extracted'],
                'document_urls_found': doc_analysis['document_urls_found'],
                'document_types_found': doc_analysis['document_types_found'],
                'has_extractable_documents': doc_analysis['total_documents_processed'] > 0
            }
        
        self.logger.info(f"Summary generated: {len(all_emails)} emails, {total_attachments} attachments, "
                        f"{len(domains)} domains, {doc_analysis.get('total_documents_processed', 0) if doc_analysis else 0} documents processed")
        
        return summary

    # Include all the original helper methods from the previous implementation
    def _extract_streamlined_headers(self, message: Message) -> Dict[str, Any]:
        """Extract essential headers only."""
        headers = {}
        
        essential_headers = {
            'from': 'From',
            'to': 'To',
            'subject': 'Subject', 
            'date': 'Date',
            'message_id': 'Message-ID'
        }
        
        for key, header_name in essential_headers.items():
            value = message.get(header_name)
            if value:
                headers[key] = str(value).strip()
        
        return headers

    def _extract_streamlined_body(self, message: Message) -> Dict[str, Any]:
        """Extract body with streamlined format."""
        body = {
            'text': None,
            'html': None,
            'has_html': False
        }
        
        plain_text = None
        html_content = None
        
        if message.is_multipart():
            for part in message.walk():
                content_type = part.get_content_type()
                
                if content_type == 'text/plain' and not plain_text:
                    plain_text = self._extract_text_content(part)
                elif content_type == 'text/html' and not html_content:
                    html_content = self._extract_text_content(part)
        else:
            content_type = message.get_content_type()
            content = self._extract_text_content(message)
            
            if content_type == 'text/plain':
                plain_text = content
            elif content_type == 'text/html':
                html_content = content

        # Set body content
        if plain_text and plain_text.strip():
            body['text'] = plain_text.strip()
        elif html_content:
            # Convert HTML to text if no plain text available
            converted = self.html_converter.convert(html_content)
            if converted and converted.strip():
                body['text'] = converted.strip()

        if html_content and html_content.strip():
            body['has_html'] = True
            # Store truncated HTML for analysis
            if len(html_content) > 500:
                body['html'] = html_content[:500] + "..."
            else:
                body['html'] = html_content

        return body

    def _process_attachments_streamlined(self, message: Message, depth: int) -> tuple:
        """Process attachments with streamlined format - FIXED VERSION."""
        attachments = []
        nested_emails = []
        
        if not message.is_multipart():
            # CRITICAL FIX: Check single-part messages for nested emails
            if self._detect_nested_email(message):
                self.logger.info("Single-part message contains nested email")
                nested_email = self._extract_nested_email_streamlined(message, depth + 1)
                if nested_email:
                    nested_email['source_attachment'] = 'embedded_single_part'
                    nested_emails.append(nested_email)
            return attachments, nested_emails
        
        for part in message.get_payload():
            disposition = part.get('Content-Disposition', '').lower()
            filename = part.get_filename()
            content_type = part.get_content_type()
            
            # CRITICAL FIX: Clean null bytes from filename
            if filename:
                filename = filename.strip('\x00')
            
            # ADDITIONAL FIX: Use bool() to avoid None evaluation issues
            is_attachment = 'attachment' in disposition or bool(filename)
            
            # Handle explicit attachments
            if is_attachment:
                attachment = self._build_streamlined_attachment(part, depth)
                attachments.append(attachment)
                
                # Check for nested email in attachment
                if attachment.get('contains_email'):
                    nested_email = self._extract_nested_email_streamlined(part, depth + 1)
                    if nested_email:
                        nested_email['source_attachment'] = filename or f"attachment_{len(attachments)}"
                        nested_emails.append(nested_email)
            
            # Handle message/rfc822 parts (even if not marked as attachments)
            elif content_type == 'message/rfc822':
                self.logger.debug(f"Found message/rfc822 part at depth {depth}")
                nested_email = self._extract_nested_email_streamlined(part, depth + 1)
                if nested_email:
                    nested_email['source_attachment'] = filename or f"embedded_rfc822_{len(nested_emails)}"
                    nested_emails.append(nested_email)
            
            # Handle other parts that might contain nested emails
            elif self._detect_nested_email(part):
                self.logger.debug(f"Found nested email in non-attachment part: {content_type}")
                nested_email = self._extract_nested_email_streamlined(part, depth + 1)
                if nested_email:
                    nested_email['source_attachment'] = filename or f"embedded_email_{len(nested_emails)}"
                    nested_emails.append(nested_email)
        
        return attachments, nested_emails

    # Include all remaining helper methods from the original implementation...
    # (I'll include the key ones here for completeness)
    
    def _extract_attachment_filename(self, part: Message) -> str:
        """Enhanced filename extraction with multiple fallback methods."""
        # Method 1: Standard get_filename()
        filename = part.get_filename()
        if filename:
            filename = filename.strip('\x00').strip()
            if filename and filename != 'unknown':
                return filename
        
        # Method 2: Parse Content-Disposition header manually
        content_disposition = part.get('Content-Disposition', '')
        if content_disposition:
            import re
            filename_match = re.search(r'filename\s*=\s*["\']?([^"\';\r\n]+)["\']?', content_disposition, re.IGNORECASE)
            if filename_match:
                filename = filename_match.group(1).strip().strip('\x00')
                if filename:
                    return filename
        
        # Method 3: Generate filename based on content type
        content_type = part.get_content_type()
        type_extensions = {
            'text/plain': '.txt',
            'text/html': '.html',
            'application/pdf': '.pdf',
            'application/msword': '.doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
            'application/vnd.ms-excel': '.xls',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
        }
        
        extension = type_extensions.get(content_type, '')
        if '/' in content_type:
            base_name = content_type.split('/')[1].replace('-', '_')
        else:
            base_name = 'attachment'
        
        return f"{base_name}{extension}" if extension else f"{base_name}_file"

    def _categorize_attachment_type(self, content_type: str, filename: str) -> str:
        """Categorize attachment type for streamlined output."""
        # Check detected mime type from content analysis first
        if content_type.startswith('image/'):
            return 'image'
        elif content_type.startswith('video/'):
            return 'video'
        elif content_type.startswith('audio/'):
            return 'audio'
        elif content_type in ['message/rfc822', 'application/vnd.ms-outlook']:
            return 'email'
        elif content_type.startswith('text/'):
            return 'text'
        elif 'pdf' in content_type:
            return 'document'
        elif any(x in content_type for x in ['word', 'excel', 'powerpoint', 'office']):
            return 'document'
        elif 'zip' in content_type or 'archive' in content_type:
            return 'archive'
        elif 'executable' in content_type or (filename and filename.endswith('.exe')):
            return 'executable'
        else:
            return 'other'

    def _extract_nested_email_streamlined(self, part: Message, depth: int) -> Optional[Dict[str, Any]]:
        """Extract nested email with streamlined format."""
        try:
            if part.get_content_type() == 'message/rfc822':
                payload_list = part.get_payload()
                if isinstance(payload_list, list) and len(payload_list) > 0:
                    nested_message = payload_list[0]
                else:
                    return None
            else:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    from email.parser import BytesParser
                    parser = BytesParser(policy=email.policy.default)
                    nested_message = parser.parsebytes(payload)
                else:
                    return None
            
            if nested_message:
                return self._build_streamlined_email(nested_message, depth)
                
        except Exception as e:
            self.logger.error(f"Error extracting nested email at depth {depth}: {e}")
        
        return None

    def _detect_nested_email(self, part: Message) -> bool:
        """Detect if a part contains a nested email."""
        content_type = part.get_content_type()
        
        if content_type in ['message/rfc822', 'message/partial', 'message/external-body']:
            return True
        
        filename = part.get_filename()
        if filename:
            email_extensions = ['.eml', '.msg', '.email']
            for ext in email_extensions:
                if filename.lower().endswith(ext):
                    return True
        
        # Check content for email patterns
        try:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload_str = payload.decode('utf-8', errors='ignore')
            else:
                payload_str = str(payload)
            
            email_indicators = ['From:', 'To:', 'Subject:', 'Date:', 'Message-ID:']
            header_count = sum(1 for indicator in email_indicators if indicator in payload_str[:2000])
            
            return header_count >= 3
        except Exception:
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
                charset = part.get_content_charset() or 'utf-8'
                
                try:
                    content = payload.decode(charset, errors='ignore')
                except (UnicodeDecodeError, LookupError):
                    for fallback_charset in ['utf-8', 'latin1', 'cp1252']:
                        try:
                            content = payload.decode(fallback_charset, errors='ignore')
                            break
                        except (UnicodeDecodeError, LookupError):
                            continue
                    else:
                        content = payload.decode('utf-8', errors='replace')
                        
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
            'parser_version': '2.1',  # Updated version
            'parsed_at': datetime.utcnow().isoformat() + 'Z',
            'source_file': 'unknown',
            'total_depth': max_depth,
            'total_emails': total_emails,
            'total_attachments': total_attachments
        }

    def _count_structure(self, message: Message, current_depth: int) -> tuple:
        """Count total emails, attachments, and max depth."""
        email_count = 1
        attachment_count = 0
        max_depth = current_depth
        
        if message.is_multipart():
            for part in message.get_payload():
                disposition = part.get('Content-Disposition', '').lower()
                content_type = part.get_content_type()
                
                if 'attachment' in disposition or bool(part.get_filename()):
                    attachment_count += 1
                    
                    if self._detect_nested_email(part):
                        try:
                            if part.get_content_type() == 'message/rfc822':
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
                                nested_emails, nested_attachments, nested_depth = self._count_structure(
                                    nested_message, current_depth + 1
                                )
                                email_count += nested_emails
                                attachment_count += nested_attachments
                                max_depth = max(max_depth, nested_depth)
                                
                        except Exception:
                            pass
                
                elif content_type == 'message/rfc822':
                    try:
                        nested_message = part.get_payload(0)
                        if nested_message:
                            nested_emails, nested_attachments, nested_depth = self._count_structure(
                                nested_message, current_depth + 1
                            )
                            email_count += nested_emails
                            attachment_count += nested_attachments
                            max_depth = max(max_depth, nested_depth)
                    except Exception:
                        pass
        
        return email_count, attachment_count, max_depth

    def _extract_auth_results(self, email_obj: Dict[str, Any]) -> Dict[str, str]:
        """Extract authentication results from headers."""
        return {
            'spf': 'unknown',
            'dkim': 'unknown', 
            'dmarc': 'unknown'
        }

    # Include verbose mode methods for backward compatibility...
    def _extract_verbose_structure(self, message: Message, depth: int = 0) -> Dict[str, Any]:
        """Keep original verbose implementation for backward compatibility."""
        """Extract comprehensive email structure with attachments and nested emails (original verbose format)."""
        self.logger.info(f"Extracting verbose email structure at depth {depth}")
        
        structure = {
            'type': 'email',
            'depth': depth,
            'headers': self._extract_headers(message),
            'content_info': self._analyze_content_type(message),
            'body': self._extract_email_body(message),
            'parts': [],
            'attachments': [],
            'nested_emails': [],
            'part_count': 0,
            'attachment_count': 0,
            'nested_email_count': 0,
            'url_analysis': None
        }
        
        try:
            if message.is_multipart():
                self.logger.info(f"Processing multipart message with {len(message.get_payload())} parts")
                
                for i, part in enumerate(message.get_payload()):
                    self.logger.debug(f"Processing part {i} at depth {depth}")
                    
                    part_info = {
                        'part_index': i,
                        'content_type': part.get_content_type(),
                        'content_disposition': part.get('Content-Disposition'),
                        'filename': part.get_filename(),
                        'is_attachment': False,
                        'is_nested_email': False
                    }
                    
                    disposition = part.get('Content-Disposition', '').lower()
                    # FIXED: Use bool() to avoid None evaluation issues
                    if 'attachment' in disposition or bool(part.get_filename()):
                        part_info['is_attachment'] = True
                        attachment = self._parse_attachment(part, depth)
                        structure['attachments'].append(attachment)
                        
                        if attachment.get('is_nested_email'):
                            structure['nested_emails'].append(attachment['nested_email'])
                            structure['nested_email_count'] += 1
                        
                        structure['attachment_count'] += 1
                    
                    structure['parts'].append(part_info)
                    structure['part_count'] += 1
            else:
                self.logger.info("Processing single-part message")
                if self._detect_nested_email(message):
                    self.logger.info("Single-part message contains nested email")
                    attachment = self._parse_attachment(message, depth)
                    structure['attachments'].append(attachment)
                    if attachment.get('is_nested_email'):
                        structure['nested_emails'].append(attachment['nested_email'])
                        structure['nested_email_count'] += 1
                    structure['attachment_count'] += 1
            
            # Add URL analysis if analyzer is available (only at top level to avoid recursion)
            if self.url_analyzer and depth == 0:
                try:
                    self.logger.info("Performing URL analysis on email structure")
                    url_analysis = self.url_analyzer.analyze_email_urls(structure)
                    structure['url_analysis'] = self.url_analyzer.get_serializable_analysis(url_analysis)
                    self.logger.info(f"URL analysis complete: {structure['url_analysis']['summary']}")
                except Exception as e:
                    self.logger.error(f"Error during URL analysis: {e}")
                    structure['url_analysis'] = {'error': str(e)}
            
        except Exception as e:
            self.logger.error(f"Error extracting email structure: {e}")
            structure['parsing_error'] = str(e)
        
        self.logger.info(f"Completed structure extraction at depth {depth}: "
                        f"{structure['part_count']} parts, "
                        f"{structure['attachment_count']} attachments, "
                        f"{structure['nested_email_count']} nested emails")
        
        return structure

    # Keep all original helper methods for verbose mode
    def _extract_headers(self, message: Message) -> Dict[str, Any]:
        """Extract and analyze email headers."""
        self.logger.debug("Extracting headers...")
        headers = {}
        
        try:
            standard_headers = ['From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 
                              'Message-ID', 'Content-Type', 'Content-Transfer-Encoding']
            
            for header in standard_headers:
                value = message.get(header)
                if value:
                    headers[header.lower().replace('-', '_')] = str(value)
                    self.logger.debug(f"Found header {header}: {value}")
            
            all_headers = {}
            for key, value in message.items():
                all_headers[key.lower().replace('-', '_')] = str(value)
            
            headers['all_headers'] = all_headers
            headers['header_count'] = len(all_headers)
            
            self.logger.info(f"Extracted {len(all_headers)} headers")
            
        except Exception as e:
            self.logger.error(f"Error extracting headers: {e}")
            headers['error'] = f"Header extraction failed: {e}"
            
        return headers
    
    def _analyze_content_type(self, message: Message) -> Dict[str, Any]:
        """Analyze content type and encoding information."""
        self.logger.debug("Analyzing content type...")
        
        content_info = {
            'content_type': 'unknown',
            'main_type': 'unknown',
            'sub_type': 'unknown',
            'charset': None,
            'boundary': None,
            'encoding': None,
            'is_multipart': False
        }
        
        try:
            content_type = message.get_content_type()
            content_info['content_type'] = content_type
            content_info['main_type'] = message.get_content_maintype()
            content_info['sub_type'] = message.get_content_subtype()
            content_info['is_multipart'] = message.is_multipart()
            
            charset = message.get_content_charset()
            if charset:
                content_info['charset'] = charset
            
            if content_info['is_multipart']:
                boundary = message.get_boundary()
                if boundary:
                    content_info['boundary'] = boundary
            
            encoding = message.get('Content-Transfer-Encoding')
            if encoding:
                content_info['encoding'] = encoding
                
            self.logger.debug(f"Content type analysis: {content_info}")
            
        except Exception as e:
            self.logger.error(f"Error analyzing content type: {e}")
            content_info['error'] = f"Content type analysis failed: {e}"
            
        return content_info
    
    def _extract_email_body(self, message: Message) -> Dict[str, Any]:
        """Extract email body content with HTML conversion."""
        self.logger.debug("Extracting email body content...")
        
        body_info = {
            'plain_text': None,
            'html_content': None,
            'body_type': 'none',
            'truncated': False,
            'char_count': 0
        }
        
        try:
            if message.is_multipart():
                self.logger.debug("Processing multipart message for body extraction")
                
                for part in message.walk():
                    content_type = part.get_content_type()
                    
                    if content_type == 'text/plain' and not body_info['plain_text']:
                        try:
                            text_content = self._extract_text_content(part)
                            if text_content and text_content.strip():
                                body_info['plain_text'] = text_content.strip()
                                body_info['body_type'] = 'plain'
                                body_info['char_count'] = len(body_info['plain_text'])
                                self.logger.debug(f"Found plain text body ({body_info['char_count']} chars)")
                        except Exception as e:
                            self.logger.debug(f"Error extracting plain text: {e}")
                    
                    elif content_type == 'text/html' and not body_info['html_content']:
                        try:
                            html_content = self._extract_text_content(part)
                            if html_content and html_content.strip():
                                body_info['html_content'] = html_content.strip()
                                self.logger.debug(f"Found HTML body ({len(body_info['html_content'])} chars)")
                                
                                if not body_info['plain_text']:
                                    plain_from_html = self.html_converter.convert(body_info['html_content'])
                                    if plain_from_html and plain_from_html.strip():
                                        body_info['plain_text'] = plain_from_html.strip()
                                        body_info['body_type'] = 'html_converted'
                                        body_info['char_count'] = len(body_info['plain_text'])
                                        self.logger.debug(f"Converted HTML to text ({body_info['char_count']} chars)")
                        except Exception as e:
                            self.logger.debug(f"Error extracting HTML: {e}")
            else:
                content_type = message.get_content_type()
                self.logger.debug(f"Processing single-part message: {content_type}")
                
                try:
                    content = self._extract_text_content(message)
                    if content:
                        content = content.strip()
                        
                        if content_type == 'text/plain':
                            body_info['plain_text'] = content
                            body_info['body_type'] = 'plain'
                            body_info['char_count'] = len(content)
                        elif content_type == 'text/html':
                            body_info['html_content'] = content
                            plain_from_html = self.html_converter.convert(content)
                            if plain_from_html and plain_from_html.strip():
                                body_info['plain_text'] = plain_from_html.strip()
                                body_info['body_type'] = 'html_converted'
                                body_info['char_count'] = len(body_info['plain_text'])
                        else:
                            body_info['plain_text'] = content
                            body_info['body_type'] = 'unknown'
                            body_info['char_count'] = len(content)
                except Exception as e:
                    self.logger.debug(f"Error extracting single-part content: {e}")
            
            if body_info['html_content'] and len(body_info['html_content']) > 50:
                body_info['html_preview'] = body_info['html_content'][:50] + "... [HTML CONTENT TRUNCATED FOR BREVITY]"
                body_info['truncated'] = True
                del body_info['html_content']
            elif body_info['html_content']:
                body_info['html_preview'] = body_info['html_content'] + " [HTML CONTENT DETECTED]"
                del body_info['html_content']
            
            self.logger.info(f"Body extraction complete: type={body_info['body_type']}, "
                           f"chars={body_info['char_count']}, truncated={body_info['truncated']}")
            
        except Exception as e:
            self.logger.error(f"Error extracting email body: {e}")
            body_info['error'] = str(e)
        
        return body_info
    
    def _extract_text_content(self, part: Message) -> Optional[str]:
        """Extract and decode text content from a message part."""
        try:
            payload = part.get_payload(decode=True)
            
            if payload is None:
                payload = part.get_payload(decode=False)
                if isinstance(payload, list):
                    return None
            
            if isinstance(payload, bytes):
                charset = part.get_content_charset() or 'utf-8'
                
                encoding = part.get('Content-Transfer-Encoding', '').lower()
                
                if encoding == 'quoted-printable':
                    try:
                        payload = quopri.decodestring(payload)
                    except Exception as e:
                        self.logger.debug(f"Manual quoted-printable decode failed: {e}")
                elif encoding == 'base64':
                    try:
                        payload = base64.b64decode(payload)
                    except Exception as e:
                        self.logger.debug(f"Manual base64 decode failed: {e}")
                
                try:
                    content = payload.decode(charset, errors='ignore')
                except (UnicodeDecodeError, LookupError):
                    for fallback_charset in ['utf-8', 'latin1', 'cp1252']:
                        try:
                            content = payload.decode(fallback_charset, errors='ignore')
                            break
                        except (UnicodeDecodeError, LookupError):
                            continue
                    else:
                        content = payload.decode('utf-8', errors='replace')
                        
            elif isinstance(payload, str):
                content = payload
            else:
                content = str(payload)
            
            return content
            
        except Exception as e:
            self.logger.error(f"Error extracting text content: {e}")
            return None
    
    def _detect_nested_email(self, part: Message) -> bool:
        """Detect if a part contains a nested email."""
        content_type = part.get_content_type()
        filename = part.get_filename()
        
        self.logger.debug(f"Checking for nested email - Content-Type: {content_type}, Filename: {filename}")
        
        # CRITICAL: Check content type first - this should catch message/rfc822
        if content_type in ['message/rfc822', 'message/partial', 'message/external-body']:
            self.logger.info(f"Detected nested email by content type: {content_type}")
            return True
        
        if filename:
            email_extensions = ['.eml', '.msg', '.email']
            for ext in email_extensions:
                if filename.lower().endswith(ext):
                    self.logger.info(f"Detected nested email by filename: {filename}")
                    return True
        
        try:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                try:
                    payload_str = payload.decode('utf-8')
                except UnicodeDecodeError:
                    payload_str = payload.decode('latin-1', errors='ignore')
            else:
                payload_str = str(payload)
            
            email_indicators = ['From:', 'To:', 'Subject:', 'Date:', 'Message-ID:', 'Received:', 'Return-Path:']
            header_matches = {}
            
            for indicator in email_indicators:
                if indicator in payload_str[:2000]:
                    header_matches[indicator] = payload_str.find(indicator)
                    
            header_count = len(header_matches)
            self.logger.debug(f"Found email headers: {list(header_matches.keys())} (count: {header_count})")
            
            if header_count >= 3:
                self.logger.info(f"Detected nested email by header pattern analysis ({header_count} headers found)")
                return True
                
        except Exception as e:
            self.logger.debug(f"Error in nested email detection: {e}")
        
        return False
    
    def _parse_attachment(self, part: Message, depth: int = 0) -> Dict[str, Any]:
        """Parse individual attachment with content analysis."""
        self.logger.info(f"Parsing attachment at depth {depth}")
        
        attachment_info = {
            'type': 'attachment',
            'depth': depth,
            'content_type': part.get_content_type(),
            'filename': part.get_filename(),
            'size': None,
            'encoding': part.get('Content-Transfer-Encoding'),
            'is_nested_email': False,
            'nested_email': None,
            'content_disposition': part.get('Content-Disposition'),
            'content_analysis': {}
        }
        
        try:
            payload = part.get_payload(decode=True)
            if payload:
                attachment_info['size'] = len(payload)
                
                self.logger.debug(f"Performing content analysis for attachment: {attachment_info['filename']}")
                content_analysis = self.content_analyzer.analyze_content(
                    payload, 
                    attachment_info['filename'], 
                    attachment_info['content_type']
                )
                
                attachment_info['content_analysis'] = content_analysis.__dict__
                
                if content_analysis.detected_type and content_analysis.confidence > 0.7:
                    if content_analysis.mime_type != attachment_info['content_type']:
                        self.logger.info(f"Content analysis override: {attachment_info['content_type']} -> {content_analysis.mime_type}")
                        attachment_info['fingerprinted_content_type'] = content_analysis.mime_type
            
            if self._detect_nested_email(part):
                attachment_info['is_nested_email'] = True
                self.logger.info("Processing nested email attachment")
                
                try:
                    if part.get_content_type() == 'message/rfc822':
                        nested_payload = part.get_payload(0) if part.get_payload() else None
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
                        attachment_info['nested_email'] = self.extract_structure(nested_payload, depth + 1, verbose=True)
                        self.logger.info(f"Successfully parsed nested email at depth {depth + 1}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to parse nested email: {e}")
                    attachment_info['nested_email_error'] = str(e)
            
        except Exception as e:
            self.logger.error(f"Error parsing attachment: {e}")
            attachment_info['error'] = str(e)
        
        return attachment_info