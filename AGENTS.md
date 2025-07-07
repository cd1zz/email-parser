# Email Parser - AGENTS.md Guide for AI Agents

This AGENTS.md file provides comprehensive guidance for AI agents working with the email parser codebase. The project is a sophisticated email parsing library with advanced document processing, URL analysis, and security-focused content processing capabilities.

## Project Overview for AI Agents

The email parser is a comprehensive Python library designed for cybersecurity applications, email forensics, and automated email analysis workflows. AI agents should understand that this project prioritizes security, robustness, and comprehensive content extraction over simple email parsing.

### Core Philosophy for AI Agents
- **Security-First Approach**: Always consider security implications when modifying code
- **Comprehensive Analysis**: The parser should extract maximum information from emails and attachments
- **Error Resilience**: Code should handle malformed, suspicious, or edge-case email formats gracefully
- **Extensible Architecture**: Maintain clean interfaces and modular design for easy extension

## Project Structure for AI Agent Navigation

```
standalone/
├── email_parser/
│   ├── __init__.py                     # Factory function - AI agents start here for parser creation
│   ├── parser.py                       # Main orchestration class - core parsing logic
│   ├── structure_extractor.py          # Primary extraction logic with document processing
│   ├── cli.py                          # Command-line interface - reference for user-facing features
│   ├── content_analyzer.py             # File type detection and metadata extraction
│   ├── converters.py                   # HTML to text conversion with Unicode cleanup
│   ├── normalizers.py                  # Content normalization (especially UTF-16 handling)
│   ├── interfaces.py                   # Abstract base classes - follow these for new components
│   ├── parsers/                        # Format-specific parsers
│   │   ├── eml_parser.py               # Standard EML email files
│   │   ├── msg_parser.py               # Microsoft Outlook MSG files (complex)
│   │   ├── mbox_parser.py              # MBOX format files
│   │   └── proofpoint_detector.py      # Enhanced Proofpoint email detection/unwrapping
│   ├── extractors/                     # Content extraction modules
│   │   ├── url_analyzer.py             # URL analysis coordination
│   │   ├── url_extractor.py            # URL extraction with document support
│   │   ├── url_processor.py            # URL processing and expansion
│   │   └── document_extractor.py       # Document text extraction (PDF, Word, Excel)
│   └── url_processing/                 # Legacy URL processing utilities
├── diagnostics/                        # Diagnostic and testing tools
│   ├── excel_diagnostic.py             # Comprehensive Excel analysis tool
│   ├── msg_diagnostic.py               # MSG file diagnostic analysis
│   └── proofpoint_diagnostic.py        # Proofpoint email testing
└── test_emails/                        # Sample files for testing

function-app/
├── function_app.py                    # Azure Functions HTTP app
├── requirements.txt                   # Dependencies for the function
├── email_parser/                      # Same parser packaged for Functions
└── shared/                            # Request/response utilities
```

### Key Components AI Agents Should Understand

- **EmailParser**: Main orchestration class that delegates to format-specific parsers
- **EmailStructureExtractor**: Core extraction logic with document processing support
- **ProofpointDetector**: Critical security component for unwrapping Proofpoint emails
- **DocumentTextExtractor**: Comprehensive document analysis (Excel URL extraction is especially complex)
- **UrlAnalyzer**: Coordinates URL extraction across email body, attachments, and documents

## Coding Conventions for AI Agents

### General Python Standards for AI Agent Code

- **Follow PEP 8**: Use 4-space indentation, 79-character line limits for code, 72 for docstrings
- **Type Hints**: Always use type hints for function parameters and return values
- **Docstrings**: Use Google-style docstrings for all public methods and classes
- **Error Handling**: Prefer specific exceptions over generic Exception catching
- **Logging**: Use the provided logger, never print() statements

```python
# CORRECT: AI agents should follow this pattern
def extract_urls_from_text(self, text: str, source: str) -> List[str]:
    """Extract URLs from text content using comprehensive patterns.
    
    Args:
        text: The text content to analyze
        source: Source identifier for debugging/tracking
        
    Returns:
        List of extracted URLs
        
    Raises:
        ValueError: If text is None or empty
    """
    if not text:
        raise ValueError("Text content cannot be empty")
    
    self.logger.debug(f"Extracting URLs from {source} ({len(text)} chars)")
    # Implementation here
```

### Email Parser Specific Conventions for AI Agents

- **Content Validation**: Always validate content types and handle mismatches
- **Unicode Handling**: Be especially careful with UTF-16 content (common in MSG files)
- **Base64 Detection**: Many security services embed emails in base64 - always check for this
- **Error Recovery**: Log errors but continue processing when possible
- **Memory Efficiency**: Handle large attachments and email chains carefully

```python
# CORRECT: Content type validation pattern AI agents should follow
def _validate_content_type(self, content: str, declared_type: str) -> Dict[str, Any]:
    """Validate declared content type against actual content."""
    validation_result = {
        'declared_type': declared_type,
        'detected_type': self._detect_actual_type(content),
        'confidence': 0.0,
        'is_mismatch': False
    }
    
    if validation_result['detected_type'] != declared_type:
        validation_result['is_mismatch'] = True
        self.logger.warning(f"Content type mismatch: {declared_type} vs {validation_result['detected_type']}")
    
    return validation_result
```

### Document Processing Conventions for AI Agents

- **Comprehensive Extraction**: Always extract both text content AND URLs from documents
- **Excel Special Handling**: Excel files require ZIP analysis for relationship files (OneDrive links)
- **Fallback Methods**: Implement multiple extraction methods (pandas, textract, manual parsing)
- **URL Deduplication**: Remove schema URLs but preserve real external links

```python
# CORRECT: Excel URL extraction pattern for AI agents
def _extract_excel_urls(self, excel_data: bytes) -> List[str]:
    """Extract URLs from Excel files including relationship files."""
    urls = set()
    
    # Method 1: Pandas for worksheet data
    try:
        dfs = pd.read_excel(io.BytesIO(excel_data), sheet_name=None)
        for sheet_name, df in dfs.items():
            # Extract URLs from dataframe content
            pass
    except Exception as e:
        self.logger.debug(f"Pandas extraction failed: {e}")
    
    # Method 2: ZIP analysis for relationship files (CRITICAL for OneDrive links)
    try:
        with zipfile.ZipFile(io.BytesIO(excel_data), 'r') as zip_file:
            for file_path in zip_file.namelist():
                if file_path.endswith('.rels'):  # Relationship files contain URLs
                    content = zip_file.read(file_path).decode('utf-8')
                    file_urls = self._extract_urls_from_text(content)
                    urls.update(url for url in file_urls if not self._is_schema_url(url))
    except Exception as e:
        self.logger.debug(f"ZIP analysis failed: {e}")
    
    return list(urls)
```

## Interface Implementation Guidelines for AI Agents

### Adding New Format Parsers

AI agents should implement the `EmailFormatParser` interface when adding support for new email formats:

```python
from email_parser.interfaces import EmailFormatParser
from typing import Optional, Tuple
from email.message import Message

class NewFormatParser(EmailFormatParser):
    """AI agents should follow this pattern for new parsers."""
    
    def can_parse(self, data: bytes, filename: Optional[str] = None) -> Tuple[bool, float]:
        """Return (can_parse_boolean, confidence_score)."""
        # Check magic bytes, file extension, content patterns
        confidence = 0.0
        can_parse = False
        
        # Implementation logic here
        
        return can_parse, confidence
    
    def parse(self, data: bytes, filename: Optional[str] = None) -> Optional[Message]:
        """Parse data into standard email.message.Message object."""
        try:
            # Conversion logic here
            return parsed_message
        except Exception as e:
            self.logger.error(f"Parsing failed: {e}")
            return None
```

### Adding Document Extractors

AI agents should extend the `DocumentTextExtractor` class for new document types:

```python
def _extract_new_document_type(self, data: bytes, filename: str) -> DocumentExtractionResult:
    """AI agents should follow this pattern for new document extractors."""
    try:
        # Extraction logic
        extracted_text = self._perform_extraction(data)
        urls_found = self._extract_urls_from_text(extracted_text)
        
        return DocumentExtractionResult(
            text_content=extracted_text,
            success=True,
            document_type='new_type',
            extraction_method='custom_method',
            metadata={
                'character_count': len(extracted_text),
                'urls_found': urls_found,
                'extraction_notes': 'Successfully processed'
            }
        )
    except Exception as e:
        return DocumentExtractionResult(
            success=False,
            error_message=f"Extraction failed: {str(e)}",
            document_type='new_type'
        )
```

## Testing Requirements for AI Agents

AI agents should run tests with these commands before submitting code:

```bash
# Run all tests
python -m pytest

# Run specific test file
python -m pytest tests/test_document_extractor.py

# Run with coverage
python -m pytest --cov=email_parser

# Test CLI functionality
python -m email_parser.cli test_emails/sample.msg --verbose

# Test diagnostics
python diagnostics/excel_diagnostic.py
python diagnostics/msg_diagnostic.py
python diagnostics/proofpoint_diagnostic.py
```

### Test Data Patterns for AI Agents

When creating tests, AI agents should use these patterns:

```python
# CORRECT: Test pattern for AI agents
class TestDocumentExtractor(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.extractor = DocumentTextExtractor(self.logger)
        
        # Create test data
        self.sample_pdf = b'%PDF-1.4...'  # Valid PDF magic bytes
        self.sample_excel = b'\xd0\xcf\x11\xe0...'  # Valid Excel OLE header
    
    def test_pdf_extraction_success(self):
        """Test successful PDF text extraction."""
        result = self.extractor.extract_text(self.sample_pdf, 'test.pdf', 'application/pdf')
        
        self.assertTrue(result.success)
        self.assertEqual(result.document_type, 'pdf')
        self.assertIsNotNone(result.text_content)
    
    def test_excel_url_extraction(self):
        """Test Excel URL extraction including relationship files."""
        result = self.extractor.extract_text(self.sample_excel, 'test.xlsx')
        
        if result.success and result.metadata:
            urls_found = result.metadata.get('urls_found', [])
            # Verify URLs were extracted from relationship files
            self.assertIsInstance(urls_found, list)
```

## Security Considerations for AI Agents

### Security-First Patterns AI Agents Must Follow

```python
# CORRECT: Security validation pattern
def _validate_attachment_safety(self, data: bytes, filename: str) -> Dict[str, Any]:
    """AI agents should always validate attachments for security."""
    analysis = self.content_analyzer.analyze_content(data, filename)
    
    security_flags = {
        'is_executable': analysis.detected_type in ['exe', 'dll', 'bat', 'cmd'],
        'has_macros': 'macro' in analysis.metadata.get('features', []),
        'suspicious_mime': analysis.declared_mime_type != analysis.detected_type,
        'oversized': len(data) > 50 * 1024 * 1024,  # 50MB limit
    }
    
    if any(security_flags.values()):
        self.logger.warning(f"Security flags detected for {filename}: {security_flags}")
    
    return security_flags

# CORRECT: URL validation pattern
def _validate_url_safety(self, url: str) -> bool:
    """AI agents should validate URLs before processing."""
    # Check for dangerous protocols
    dangerous_protocols = ['file://', 'javascript:', 'data:', 'vbscript:']
    if any(url.lower().startswith(proto) for proto in dangerous_protocols):
        self.logger.warning(f"Dangerous protocol detected in URL: {url}")
        return False
    
    # Check for extremely long URLs (potential DoS)
    if len(url) > 2048:
        self.logger.warning(f"Extremely long URL detected: {len(url)} chars")
        return False
    
    return True
```

### Proofpoint Handling Requirements for AI Agents

AI agents working with Proofpoint detection must understand these critical patterns:

```python
# CORRECT: Proofpoint detection pattern AI agents must follow
def _detect_proofpoint_email(self, message: Message) -> bool:
    """AI agents must check both subject and content for Proofpoint indicators."""
    subject = message.get("Subject", "")
    
    # Primary indicators
    subject_indicators = ["Potential Phish:", "Suspicious Email:", "Security Alert:"]
    has_subject_indicator = any(indicator in subject for indicator in subject_indicators)
    
    # Content markers (critical for base64 emails)
    body_content = self._extract_all_content_including_base64(message)
    proofpoint_markers = [
        "---------- Begin Email Headers ----------",
        "---------- Begin Reported Email ----------"
    ]
    has_content_markers = any(marker in body_content for marker in proofpoint_markers)
    
    # High confidence: subject + content markers
    if has_subject_indicator and has_content_markers:
        return True
    
    # Medium confidence: strong content markers only
    return has_content_markers and self._has_strong_proofpoint_indicators(body_content)
```

## Pull Request Guidelines for AI Agents

When AI agents create PRs, ensure they:

1. **Include comprehensive test coverage** for new functionality
2. **Update documentation** including docstrings and CLI help text
3. **Maintain backward compatibility** unless explicitly breaking changes
4. **Include performance impact assessment** for document processing changes
5. **Security review checklist** for any changes to parsing or URL handling

### PR Description Template for AI Agents

```markdown
## Changes Made
- Brief description of changes
- Impact on existing functionality
- New features or capabilities added

## Testing Performed
- [ ] Unit tests pass
- [ ] Integration tests with sample emails
- [ ] CLI functionality verified
- [ ] Document processing tested with real files

## Security Considerations
- [ ] Input validation reviewed
- [ ] No new security vulnerabilities introduced
- [ ] Proofpoint detection still functional
- [ ] URL processing security maintained

## Performance Impact
- [ ] No significant performance regression
- [ ] Memory usage analyzed for large files
- [ ] Document processing efficiency maintained
```

## Programmatic Checks for AI Agents

Before submitting code, AI agents should run the following checks on both the
`standalone` and `function-app` code:

```bash
# Code quality checks
python -m flake8 standalone/email_parser function-app --max-line-length=88
python -m black standalone/email_parser function-app --check
python -m isort standalone/email_parser function-app --check-only

# Type checking
python -m mypy standalone/email_parser function-app/email_parser function-app/shared

# Security checks
python -m bandit -r standalone/email_parser function-app/email_parser function-app/shared

# Test suite
python -m pytest tests/ --cov=email_parser --cov-report=html

# Integration tests with real files
python -m email_parser.cli test_emails/excel_example.eml --verbose
python -m email_parser.cli test_emails/proofpoint_sample.eml --verbose

# Diagnostic tools
python diagnostics/excel_diagnostic.py
python diagnostics/msg_diagnostic.py
```

## Common Patterns AI Agents Should Follow

### Error Handling Pattern

```python
# CORRECT: Comprehensive error handling for AI agents
def process_attachment(self, attachment_data: bytes, filename: str) -> Dict[str, Any]:
    """AI agents should follow this error handling pattern."""
    result = {
        'success': False,
        'filename': filename,
        'errors': [],
        'warnings': []
    }
    
    try:
        # Validate input
        if not attachment_data:
            result['errors'].append("Empty attachment data")
            return result
        
        # Security validation
        security_check = self._validate_attachment_safety(attachment_data, filename)
        if security_check.get('is_executable'):
            result['warnings'].append("Executable attachment detected")
        
        # Process attachment
        processed_data = self._perform_processing(attachment_data)
        result.update({
            'success': True,
            'processed_data': processed_data
        })
        
    except SecurityError as e:
        result['errors'].append(f"Security error: {e}")
        self.logger.error(f"Security error processing {filename}: {e}")
    except ProcessingError as e:
        result['errors'].append(f"Processing error: {e}")
        self.logger.warning(f"Processing error for {filename}: {e}")
    except Exception as e:
        result['errors'].append(f"Unexpected error: {e}")
        self.logger.exception(f"Unexpected error processing {filename}")
    
    return result
```

### Logging Pattern

```python
# CORRECT: Logging pattern for AI agents
def extract_structure(self, message: Message, depth: int = 0) -> Dict[str, Any]:
    """AI agents should use consistent logging patterns."""
    self.logger.info(f"Starting structure extraction at depth {depth}")
    
    try:
        # Log key milestones
        self.logger.debug(f"Processing message with {len(message.get_payload()) if message.is_multipart() else 1} parts")
        
        # Process content
        structure = self._build_structure(message, depth)
        
        # Log success with metrics
        self.logger.info(
            f"Extraction complete: {structure.get('attachment_count', 0)} attachments, "
            f"{structure.get('nested_email_count', 0)} nested emails"
        )
        
        return structure
        
    except Exception as e:
        self.logger.error(f"Structure extraction failed at depth {depth}: {e}")
        raise
```

## Dependencies and Library Usage for AI Agents

### Required Dependencies AI Agents Should Know

```python
# Core email processing
import email
import email.parser
import email.policy
from email.message import Message

# Document processing
import pandas as pd  # Excel processing
import zipfile  # Excel ZIP analysis
import base64  # Base64 email detection
import io  # BytesIO operations

# Optional dependencies (check availability)
try:
    import extract_msg  # MSG file processing
    MSG_SUPPORT = True
except ImportError:
    MSG_SUPPORT = False

try:
    from pdfminer.high_level import extract_text  # PDF processing
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False
```

### Library Usage Patterns for AI Agents

```python
# CORRECT: Conditional library usage pattern
def _extract_pdf_text(self, pdf_data: bytes) -> DocumentExtractionResult:
    """AI agents should check library availability before use."""
    if not PDF_SUPPORT:
        return DocumentExtractionResult(
            success=False,
            error_message="PDF processing requires pdfminer.six library",
            document_type='pdf'
        )
    
    try:
        text = extract_text(io.BytesIO(pdf_data))
        return DocumentExtractionResult(
            text_content=text,
            success=True,
            document_type='pdf',
            extraction_method='pdfminer'
        )
    except Exception as e:
        return DocumentExtractionResult(
            success=False,
            error_message=f"PDF extraction failed: {str(e)}",
            document_type='pdf'
        )
```

All AI agents working on this codebase should prioritize security, comprehensive content extraction, and maintaining the existing architecture while extending functionality. The email parser is designed for production cybersecurity applications, so code quality and error handling are critical.