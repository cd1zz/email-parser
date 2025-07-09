"""
Centralized configuration management for Email Parser
All configurable values consolidated in one place for easy management
"""

import os
from typing import Dict, Any, List

class EmailParserConfig:
    """Configuration management for email parser with environment variable override support"""
    
    def __init__(self):
        # File Size and Processing Limits
        self.MAX_FILE_SIZE_MB = int(os.getenv('EP_MAX_FILE_SIZE_MB', 50))
        self.MIN_EMAIL_SIZE_BYTES = int(os.getenv('EP_MIN_EMAIL_SIZE_BYTES', 10))
        self.MAX_NULL_BYTES = int(os.getenv('EP_MAX_NULL_BYTES', 100))
        self.MAX_FILENAME_LENGTH = int(os.getenv('EP_MAX_FILENAME_LENGTH', 255))
        self.DOCUMENT_TEXT_LIMIT = int(os.getenv('EP_DOCUMENT_TEXT_LIMIT', 10000))
        self.DOCUMENT_TEXT_LIMIT_MIN = int(os.getenv('EP_DOCUMENT_TEXT_LIMIT_MIN', 100))
        
        # Timeouts
        self.DEFAULT_EXPANSION_TIMEOUT = float(os.getenv('EP_DEFAULT_EXPANSION_TIMEOUT', 5.0))
        self.EXPANSION_TIMEOUT_MIN = float(os.getenv('EP_EXPANSION_TIMEOUT_MIN', 1.0))
        self.EXPANSION_TIMEOUT_MAX = float(os.getenv('EP_EXPANSION_TIMEOUT_MAX', 30.0))
        self.EXPANSION_DELAY = float(os.getenv('EP_EXPANSION_DELAY', 0.5))
        self.FUNCTION_TIMEOUT_SECONDS = int(os.getenv('EP_FUNCTION_TIMEOUT_SECONDS', 300))
        
        # Email Parsing Thresholds
        self.EML_HEADER_CHECK_SIZE = int(os.getenv('EP_EML_HEADER_CHECK_SIZE', 2048))
        self.HIGH_CONFIDENCE_HEADER_COUNT = int(os.getenv('EP_HIGH_CONFIDENCE_HEADER_COUNT', 3))
        self.MEDIUM_CONFIDENCE_HEADER_COUNT = int(os.getenv('EP_MEDIUM_CONFIDENCE_HEADER_COUNT', 2))
        self.LOW_CONFIDENCE_HEADER_COUNT = int(os.getenv('EP_LOW_CONFIDENCE_HEADER_COUNT', 1))
        self.MIN_HEADER_COUNT = int(os.getenv('EP_MIN_HEADER_COUNT', 1))
        
        # MSG Parsing Configuration
        self.BASE64_LINE_WRAP_LENGTH = int(os.getenv('EP_BASE64_LINE_WRAP_LENGTH', 76))
        self.HEADER_PATTERN_CHECK_LINES = int(os.getenv('EP_HEADER_PATTERN_CHECK_LINES', 10))
        self.MIN_HEADER_PATTERNS = int(os.getenv('EP_MIN_HEADER_PATTERNS', 2))
        
        # Proofpoint Detection Thresholds
        self.STRONG_PROOFPOINT_INDICATORS = int(os.getenv('EP_STRONG_PROOFPOINT_INDICATORS', 2))
        self.EMAIL_CONTENT_INDICATORS = int(os.getenv('EP_EMAIL_CONTENT_INDICATORS', 3))
        self.MIN_EMAIL_CONTENT_LENGTH = int(os.getenv('EP_MIN_EMAIL_CONTENT_LENGTH', 200))
        self.MIN_SUBSTANTIAL_TEXT_LENGTH = int(os.getenv('EP_MIN_SUBSTANTIAL_TEXT_LENGTH', 100))
        self.MIN_REASONABLE_CONTENT_LENGTH = int(os.getenv('EP_MIN_REASONABLE_CONTENT_LENGTH', 50))
        self.VALID_EMAIL_INDICATOR_COUNT = int(os.getenv('EP_VALID_EMAIL_INDICATOR_COUNT', 3))
        self.FALLBACK_CONTENT_MIN_LENGTH = int(os.getenv('EP_FALLBACK_CONTENT_MIN_LENGTH', 200))
        self.MIN_HEADERS_LENGTH = int(os.getenv('EP_MIN_HEADERS_LENGTH', 20))
        self.PATTERN_COUNT_IN_CONTENT = int(os.getenv('EP_PATTERN_COUNT_IN_CONTENT', 2))
        self.PROOFPOINT_CONTENT_MIN = int(os.getenv('EP_PROOFPOINT_CONTENT_MIN', 200))
        
        # Content Analysis Configuration
        self.MAGIC_BYTE_CHECK_SIZE = int(os.getenv('EP_MAGIC_BYTE_CHECK_SIZE', 16))
        self.MSG_FILE_SAMPLE_CHECK_SIZE = int(os.getenv('EP_MSG_FILE_SAMPLE_CHECK_SIZE', 8192))
        self.ASCII_RATIO_CHECK_SIZE = int(os.getenv('EP_ASCII_RATIO_CHECK_SIZE', 1024))
        self.ENTROPY_CALCULATION_SIZE = int(os.getenv('EP_ENTROPY_CALCULATION_SIZE', 4096))
        
        # Document Processing
        self.MEANINGFUL_CONTENT_LIMIT = int(os.getenv('EP_MEANINGFUL_CONTENT_LIMIT', 10))
        self.MEANINGFUL_LINES_LIMIT = int(os.getenv('EP_MEANINGFUL_LINES_LIMIT', 5))
        
        # Debug and Preview Settings
        self.DEBUG_PREVIEW_CHARS = int(os.getenv('EP_DEBUG_PREVIEW_CHARS', 500))
        self.HTML_PREVIEW_CHARS = int(os.getenv('EP_HTML_PREVIEW_CHARS', 50))
        
        # URL Configuration
        self.SHORT_URL_PATH_LENGTH = int(os.getenv('EP_SHORT_URL_PATH_LENGTH', 10))
        self.SEPARATOR_LINE_MIN_LENGTH = int(os.getenv('EP_SEPARATOR_LINE_MIN_LENGTH', 5))
        
        # Supported Content Types
        self.SUPPORTED_CONTENT_TYPES = [
            "text/plain",
            "application/octet-stream",
            "application/json",
            "multipart/form-data"
        ]
        
        # Dangerous File Extensions
        self.DANGEROUS_EXTENSIONS = [".exe", ".bat", ".cmd", ".scr", ".pif"]
        
        # Image File Extensions
        self.IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.tiff']
        
        # URL Shortener Domains
        self.URL_SHORTENERS = [
            'bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly',
            'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'po.st', 'bc.vc', 'twitthis.com',
            'u.to', 'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org', 'x.co',
            'prettylinkpro.com', 'scrnch.me', 'filoops.info', 'vzturl.com', 'qr.net',
            '1url.com', 'tweez.me', 'v.gd', 'tr.im', 'link.zip.net', 'short.link',
            'rb.gy', 'shorturl.at', 'tiny.cc', 'soo.gd', 'clck.ru', 's.id', 'url.ie'
        ]
        
        # XML Schema URL Filters
        self.XML_SCHEMA_URL_FILTERS = [
            'http://schemas.',
            'http://www.w3.org/',
            'http://purl.org/',
            'http://ns.adobe.com/'
        ]
        
        # Email Headers for Detection
        self.EMAIL_HEADERS = ['From:', 'To:', 'Subject:', 'Date:', 'Message-ID:', 'MIME-Version:']
        
        # Valid Log Levels
        self.VALID_LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR"]
        
        # Default Feature Flags
        self.DEFAULT_ENABLE_URL_ANALYSIS = os.getenv('EP_DEFAULT_ENABLE_URL_ANALYSIS', 'true').lower() == 'true'
        self.DEFAULT_ENABLE_URL_EXPANSION = os.getenv('EP_DEFAULT_ENABLE_URL_EXPANSION', 'false').lower() == 'true'
        self.DEFAULT_ENABLE_DOCUMENT_PROCESSING = os.getenv('EP_DEFAULT_ENABLE_DOCUMENT_PROCESSING', 'true').lower() == 'true'
        self.DEFAULT_SHOW_DOCUMENT_TEXT = os.getenv('EP_DEFAULT_SHOW_DOCUMENT_TEXT', 'false').lower() == 'true'
        self.DEFAULT_VERBOSE = os.getenv('EP_DEFAULT_VERBOSE', 'false').lower() == 'true'
        self.DEFAULT_LOG_LEVEL = os.getenv('EP_DEFAULT_LOG_LEVEL', 'INFO')
        
        # Proofpoint Markers and Indicators
        self.PROOFPOINT_MARKERS = [
            '---------- Begin Email Headers ----------',
            '---------- Begin Reported Email ----------',
            '---------- Begin Attachment',
            '---------- End Email Headers ----------',
            '---------- End Reported Email ----------',
            '---------- End Attachment',
            'X-Proofpoint',
            'X-PFPT',
            'Proofpoint Protection'
        ]
        
        self.PROOFPOINT_SUBJECT_INDICATORS = [
            '[EXTERNAL]',
            '[SUSPICIOUS]',
            '[CAUTION]',
            'FW: [EXTERNAL]',
            'Fwd: [EXTERNAL]',
            'PHISHING',
            'SUSPECTED',
            'REPORTED'
        ]
        
    def get_config_dict(self) -> Dict[str, Any]:
        """Get all configuration values as a dictionary"""
        return {
            # File Sizes
            'max_file_size_mb': self.MAX_FILE_SIZE_MB,
            'min_email_size_bytes': self.MIN_EMAIL_SIZE_BYTES,
            'max_null_bytes': self.MAX_NULL_BYTES,
            'max_filename_length': self.MAX_FILENAME_LENGTH,
            'document_text_limit': self.DOCUMENT_TEXT_LIMIT,
            'document_text_limit_min': self.DOCUMENT_TEXT_LIMIT_MIN,
            
            # Timeouts
            'default_expansion_timeout': self.DEFAULT_EXPANSION_TIMEOUT,
            'expansion_timeout_min': self.EXPANSION_TIMEOUT_MIN,
            'expansion_timeout_max': self.EXPANSION_TIMEOUT_MAX,
            'expansion_delay': self.EXPANSION_DELAY,
            'function_timeout_seconds': self.FUNCTION_TIMEOUT_SECONDS,
            
            # Email Parsing
            'eml_header_check_size': self.EML_HEADER_CHECK_SIZE,
            'high_confidence_header_count': self.HIGH_CONFIDENCE_HEADER_COUNT,
            'medium_confidence_header_count': self.MEDIUM_CONFIDENCE_HEADER_COUNT,
            'low_confidence_header_count': self.LOW_CONFIDENCE_HEADER_COUNT,
            'min_header_count': self.MIN_HEADER_COUNT,
            
            # MSG Parsing
            'base64_line_wrap_length': self.BASE64_LINE_WRAP_LENGTH,
            'header_pattern_check_lines': self.HEADER_PATTERN_CHECK_LINES,
            'min_header_patterns': self.MIN_HEADER_PATTERNS,
            
            # Proofpoint Detection
            'strong_proofpoint_indicators': self.STRONG_PROOFPOINT_INDICATORS,
            'email_content_indicators': self.EMAIL_CONTENT_INDICATORS,
            'min_email_content_length': self.MIN_EMAIL_CONTENT_LENGTH,
            'min_substantial_text_length': self.MIN_SUBSTANTIAL_TEXT_LENGTH,
            'min_reasonable_content_length': self.MIN_REASONABLE_CONTENT_LENGTH,
            'valid_email_indicator_count': self.VALID_EMAIL_INDICATOR_COUNT,
            'fallback_content_min_length': self.FALLBACK_CONTENT_MIN_LENGTH,
            'min_headers_length': self.MIN_HEADERS_LENGTH,
            'pattern_count_in_content': self.PATTERN_COUNT_IN_CONTENT,
            'proofpoint_content_min': self.PROOFPOINT_CONTENT_MIN,
            
            # Content Analysis
            'magic_byte_check_size': self.MAGIC_BYTE_CHECK_SIZE,
            'msg_file_sample_check_size': self.MSG_FILE_SAMPLE_CHECK_SIZE,
            'ascii_ratio_check_size': self.ASCII_RATIO_CHECK_SIZE,
            'entropy_calculation_size': self.ENTROPY_CALCULATION_SIZE,
            
            # Document Processing
            'meaningful_content_limit': self.MEANINGFUL_CONTENT_LIMIT,
            'meaningful_lines_limit': self.MEANINGFUL_LINES_LIMIT,
            
            # Debug and Preview Settings
            'debug_preview_chars': self.DEBUG_PREVIEW_CHARS,
            'html_preview_chars': self.HTML_PREVIEW_CHARS,
            
            # URL Configuration
            'short_url_path_length': self.SHORT_URL_PATH_LENGTH,
            'separator_line_min_length': self.SEPARATOR_LINE_MIN_LENGTH,
            
            # Lists
            'supported_content_types': self.SUPPORTED_CONTENT_TYPES,
            'dangerous_extensions': self.DANGEROUS_EXTENSIONS,
            'image_extensions': self.IMAGE_EXTENSIONS,
            'url_shorteners': self.URL_SHORTENERS,
            'xml_schema_url_filters': self.XML_SCHEMA_URL_FILTERS,
            'email_headers': self.EMAIL_HEADERS,
            'valid_log_levels': self.VALID_LOG_LEVELS,
            
            # Feature Flags
            'default_enable_url_analysis': self.DEFAULT_ENABLE_URL_ANALYSIS,
            'default_enable_url_expansion': self.DEFAULT_ENABLE_URL_EXPANSION,
            'default_enable_document_processing': self.DEFAULT_ENABLE_DOCUMENT_PROCESSING,
            'default_show_document_text': self.DEFAULT_SHOW_DOCUMENT_TEXT,
            'default_verbose': self.DEFAULT_VERBOSE,
            'default_log_level': self.DEFAULT_LOG_LEVEL,
            
            # Proofpoint
            'proofpoint_markers': self.PROOFPOINT_MARKERS,
            'proofpoint_subject_indicators': self.PROOFPOINT_SUBJECT_INDICATORS
        }

# Create a singleton instance
config = EmailParserConfig()