# ============================================================================
# email_parser/forwarded_email_detector.py - Forwarded email detection and parsing
# ============================================================================

import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import logging
from email.message import Message
from email.parser import Parser
import email.policy


class ForwardedEmailDetector:
    """Detect and extract forwarded emails from email body content."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
        # Common forwarding patterns across different email clients
        self.forwarding_patterns = [
            # Outlook/Exchange pattern
            r'[-]{3,}\s*Original Message\s*[-]{3,}',
            r'[-]{3,}\s*Forwarded Message\s*[-]{3,}',
            r'_{10,}\s*From:',
            # Gmail pattern
            r'---------- Forwarded message ---------',
            # Apple Mail pattern
            r'Begin forwarded message:',
            # Generic patterns
            r'>> From:.*\n>> (?:Sent|Date):',
            r'On .+ wrote:',
            # Pattern from test email (handles both with and without angle brackets)
            r'From:\s*[^<\n]+<[^>]+>\s*\nSent:\s*[^\n]+\nTo:\s*[^<\n]+<[^>]+>\s*\nSubject:\s*[^\n]+',
            # Simpler pattern for without angle brackets
            r'From:\s*[^\n]+\nSent:\s*[^\n]+\nTo:\s*[^\n]+\nSubject:\s*[^\n]+',
            # Markdown-style pattern (from HTML to text conversion)
            r'\*\*From:\*\*\s*[^\n]+\n\*\*Sent:\*\*\s*[^\n]+\n\*\*To:\*\*\s*[^\n]+\n\*\*Subject:\*\*\s*[^\n]+',
        ]
        
        # Header extraction patterns
        self.header_patterns = {
            'from': [
                r'From:\s*([^\n]+)',
                r'From:\s*"?([^"<\n]+)"?\s*<([^>]+)>',
                r'From:\s*([^<\n]+<[^>]+>)',
                r'\*\*From:\*\*\s*([^\n]+)',  # Markdown style
            ],
            'to': [
                r'To:\s*([^\n]+)',
                r'To:\s*"?([^"<\n]+)"?\s*<([^>]+)>',
                r'To:\s*([^<\n]+<[^>]+>)',
                r'\*\*To:\*\*\s*([^\n]+)',  # Markdown style
            ],
            'sent': [
                r'Sent:\s*([^\n]+)',
                r'Date:\s*([^\n]+)',
                r'\*\*Sent:\*\*\s*([^\n]+)',  # Markdown style
            ],
            'subject': [
                r'Subject:\s*([^\n]+)',
                r'\*\*Subject:\*\*\s*([^\n]+)',  # Markdown style
            ],
        }
    
    def detect_forwarded_emails(self, body_text: str) -> List[Dict[str, Any]]:
        """Detect forwarded emails in body text and extract their content."""
        if not body_text:
            return []
        
        forwarded_emails = []
        
        # Try each forwarding pattern
        for pattern in self.forwarding_patterns:
            matches = list(re.finditer(pattern, body_text, re.IGNORECASE | re.MULTILINE))
            
            if matches:
                self.logger.info(f"Found {len(matches)} forwarded email(s) using pattern: {pattern[:30]}...")
                
                for i, match in enumerate(matches):
                    start_pos = match.start()
                    
                    # Extract the forwarded email content
                    # Find the next forwarding marker or end of text
                    if i + 1 < len(matches):
                        end_pos = matches[i + 1].start()
                        forwarded_content = body_text[start_pos:end_pos]
                    else:
                        forwarded_content = body_text[start_pos:]
                    
                    # Parse the forwarded email
                    parsed_forward = self._parse_forwarded_email(forwarded_content)
                    if parsed_forward:
                        forwarded_emails.append(parsed_forward)
        
        # Also check for the specific pattern from the test email (both with and without angle brackets)
        test_patterns = [
            r'From:\s*([^<\n]+<[^>]+>)\s*\nSent:\s*([^\n]+)\s*\nTo:\s*([^<\n]+<[^>]+>)\s*\nSubject:\s*([^\n]+)',
            r'From:\s*([^\n]+)\s*\nSent:\s*([^\n]+)\s*\nTo:\s*([^\n]+)\s*\nSubject:\s*([^\n]+)',
            r'\*\*From:\*\*\s*([^\n]+)\s*\n\*\*Sent:\*\*\s*([^\n]+)\s*\n\*\*To:\*\*\s*([^\n]+)\s*\n\*\*Subject:\*\*\s*([^\n]+)'
        ]
        
        test_matches = []
        for pattern in test_patterns:
            test_matches.extend(list(re.finditer(pattern, body_text, re.IGNORECASE | re.MULTILINE)))
        
        for match in test_matches:
            # Check if this match is already covered
            match_start = match.start()
            already_found = any(
                fw['position']['start'] <= match_start <= fw['position']['end'] 
                for fw in forwarded_emails
            )
            
            if not already_found:
                self.logger.info("Found forwarded email using test email pattern")
                # Extract the entire forwarded section
                start_pos = match.start()
                # Find where the forwarded content ends (usually at the next separator or end)
                forwarded_content = body_text[start_pos:]
                
                parsed_forward = self._parse_forwarded_email_simple(match, forwarded_content)
                if parsed_forward:
                    forwarded_emails.append(parsed_forward)
        
        # Remove duplicates based on position
        unique_forwards = []
        for fw in forwarded_emails:
            is_duplicate = False
            for existing in unique_forwards:
                if (abs(fw['position']['start'] - existing['position']['start']) < 50 and
                    fw['headers'].get('from') == existing['headers'].get('from') and
                    fw['headers'].get('subject') == existing['headers'].get('subject')):
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                unique_forwards.append(fw)
        
        self.logger.info(f"Total unique forwarded emails detected: {len(unique_forwards)}")
        return unique_forwards
    
    def _parse_forwarded_email_simple(self, match: re.Match, full_content: str) -> Optional[Dict[str, Any]]:
        """Parse a forwarded email from the simple pattern match."""
        try:
            groups = match.groups()
            if len(groups) >= 4:
                from_value = groups[0].strip()
                sent_value = groups[1].strip()
                to_value = groups[2].strip()
                subject_value = groups[3].strip()
                
                # Clean up markdown artifacts from headers
                from_value = from_value.replace('**', '').strip()
                sent_value = sent_value.replace('**', '').strip()
                to_value = to_value.replace('**', '').strip()
                subject_value = subject_value.replace('**', '').strip()
                
                # Extract the body content after the headers
                header_end = match.end()
                # Skip any whitespace after headers
                body_start = header_end
                while body_start < len(full_content) and full_content[body_start] in '\r\n':
                    body_start += 1
                
                # Find where this forwarded email ends
                # Look for common end markers or another forwarded email
                body_content = full_content[body_start:]
                
                # Check for end markers
                end_markers = [
                    '\n\n--',  # Signature separator
                    '\n\nFrom:',  # Another forwarded email
                    '\n\n____',  # Separator line
                    '\n\n----',  # Separator line
                    '\n\n**From:**',  # Another markdown forwarded email
                ]
                
                min_end_pos = len(body_content)
                for marker in end_markers:
                    marker_pos = body_content.find(marker)
                    if marker_pos > 0 and marker_pos < min_end_pos:
                        min_end_pos = marker_pos
                
                body_content = body_content[:min_end_pos].strip()
                
                return {
                    'type': 'forwarded_email',
                    'headers': {
                        'from': from_value,
                        'to': to_value,
                        'date': sent_value,
                        'subject': subject_value,
                    },
                    'body': {
                        'text': body_content,
                        'has_html': False
                    },
                    'position': {
                        'start': match.start(),
                        'end': match.start() + len(match.group(0)) + len(body_content)
                    },
                    'raw_content': full_content[match.start():match.start() + len(match.group(0)) + len(body_content)]
                }
        
        except Exception as e:
            self.logger.error(f"Error parsing simple forwarded email: {e}")
            return None
    
    def _parse_forwarded_email(self, content: str) -> Optional[Dict[str, Any]]:
        """Parse a forwarded email section into structured data."""
        try:
            # Extract headers
            headers = {}
            for header_name, patterns in self.header_patterns.items():
                for pattern in patterns:
                    match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
                    if match:
                        if header_name in ['from', 'to'] and len(match.groups()) > 1:
                            # Handle "Name" <email> format
                            headers[header_name] = match.group(0).replace(f'{header_name}:', '').strip()
                        else:
                            headers[header_name] = match.group(1).strip()
                        break
            
            # Map 'sent' to 'date' for consistency
            if 'sent' in headers and 'date' not in headers:
                headers['date'] = headers.pop('sent')
            
            # Clean up markdown artifacts from all headers
            for key in headers:
                headers[key] = headers[key].replace('**', '').strip()
            
            # Try to find where headers end and body begins
            body_start_patterns = [
                r'\n\n',  # Double newline
                r'\n\r\n',  # Windows style
                r'Subject:[^\n]+\n(?!\w+:)',  # After subject with no more headers
            ]
            
            body_text = ""
            body_start = len(content)
            
            for pattern in body_start_patterns:
                match = re.search(pattern, content)
                if match and match.end() < body_start:
                    body_start = match.end()
            
            if body_start < len(content):
                body_text = content[body_start:].strip()
            
            # Only return if we found meaningful headers
            if headers and any(h in headers for h in ['from', 'subject']):
                return {
                    'type': 'forwarded_email',
                    'headers': headers,
                    'body': {
                        'text': body_text,
                        'has_html': self._detect_html_content(body_text)
                    },
                    'position': {
                        'start': 0,  # Will be updated by caller
                        'end': len(content)
                    },
                    'raw_content': content
                }
                
        except Exception as e:
            self.logger.error(f"Error parsing forwarded email: {e}")
        
        return None
    
    def _detect_html_content(self, text: str) -> bool:
        """Detect if text contains HTML content."""
        html_indicators = ['<html', '<body', '<div', '<p>', '<br', '<table']
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in html_indicators)
    
    def extract_forwarded_emails_from_body(self, email_body: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract forwarded emails from an email body structure."""
        if not email_body or not isinstance(email_body, dict):
            return []
        
        # Get text content from body
        body_text = email_body.get('text', '')
        if not body_text:
            return []
        
        self.logger.debug(f"Checking body text for forwarded emails, length: {len(body_text)}")
        return self.detect_forwarded_emails(body_text)
    
    def process_email_for_forwards(self, email_obj: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
        """Process an email object and add forwarded emails as nested structure."""
        # Don't modify the original object
        import copy
        processed_email = copy.deepcopy(email_obj)
        
        # Extract forwarded emails from body
        if 'body' in processed_email:
            forwarded_emails = self.extract_forwarded_emails_from_body(processed_email['body'])
            
            if forwarded_emails:
                self.logger.info(f"Found {len(forwarded_emails)} forwarded email(s) at depth {depth}")
                
                # Add forwarded emails to nested_emails list
                if 'nested_emails' not in processed_email:
                    processed_email['nested_emails'] = []
                
                for i, fw_email in enumerate(forwarded_emails):
                    # Convert to standard email structure
                    nested_email = {
                        'level': depth + 1,
                        'headers': fw_email['headers'],
                        'body': fw_email['body'],
                        'attachments': [],
                        'nested_emails': [],
                        'urls': [],
                        'source_type': 'forwarded',
                        'source_position': fw_email['position']
                    }
                    
                    # Recursively check for more forwarded emails in this forwarded email
                    if fw_email['body'].get('text'):
                        deeper_forwards = self.detect_forwarded_emails(fw_email['body']['text'])
                        if deeper_forwards:
                            nested_email = self.process_email_for_forwards(nested_email, depth + 1)
                    
                    processed_email['nested_emails'].append(nested_email)
        
        # Process existing nested emails recursively
        if 'nested_emails' in processed_email:
            for i, nested in enumerate(processed_email['nested_emails']):
                if nested.get('source_type') != 'forwarded':  # Don't reprocess forwarded emails
                    processed_email['nested_emails'][i] = self.process_email_for_forwards(nested, depth + 1)
        
        return processed_email